// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use axum::http::HeaderMap;

#[test]
fn original_precondition_clone_retains_first_backing_and_all_duplicate_counts() {
    let mut headers = HeaderMap::new();
    let value = HeaderValue::from_str(&format!("\"{}\"", "original".repeat(32))).unwrap();
    let pointer = value.as_bytes().as_ptr();
    headers.append(header::IF_MATCH, value);
    for count in 1..=12 {
        let retained = OriginalConfigPrecondition::capture(&headers).clone();
        assert_eq!(retained.count, count);
        assert_eq!(
            retained.first.as_ref().unwrap().as_bytes().as_ptr(),
            pointer
        );
        if count == 1 {
            assert!(retained.require_strong().is_ok());
        } else {
            assert_eq!(
                retained.require_strong().unwrap_err().status(),
                StatusCode::BAD_REQUEST
            );
        }
        headers.append(header::IF_MATCH, HeaderValue::from_static("\"another\""));
    }
}

#[test]
fn conditional_read_keeps_first_field_and_existing_weak_comparison() {
    for (field, expected) in [
        ("*", true),
        (" \"tag\" ", true),
        ("W/\"tag\"", true),
        ("\"other\", W/\"tag\"", true),
        ("\"other\"", false),
        ("", false),
    ] {
        let mut headers = HeaderMap::new();
        headers.append(header::IF_NONE_MATCH, HeaderValue::from_str(field).unwrap());
        headers.append(header::IF_NONE_MATCH, HeaderValue::from_static("*"));
        let first = headers.get(header::IF_NONE_MATCH).cloned();
        drop(headers);
        assert_eq!(
            if_none_match(first.as_ref(), "W/\"tag\""),
            expected,
            "{field}"
        );
    }
    assert!(!if_none_match(None, "\"tag\""));
    let invalid = HeaderValue::from_bytes(b"\xff").unwrap();
    assert!(!if_none_match(Some(&invalid), "\"tag\""));
}

#[test]
fn original_precondition_keeps_multiplicity_and_bytes_before_translation() {
    let mut headers = HeaderMap::new();
    assert_eq!(
        OriginalConfigPrecondition::capture(&headers)
            .require_strong()
            .unwrap_err()
            .status(),
        StatusCode::PRECONDITION_REQUIRED
    );
    let wire = HeaderValue::from_static("\"dep_original.7\"");
    headers.insert(header::IF_MATCH, wire.clone());
    let original = OriginalConfigPrecondition::capture(&headers);
    headers.insert(header::IF_MATCH, HeaderValue::from_static("\"12\""));
    assert_eq!(original.require_strong().unwrap(), &wire);
    for malformed in [
        "*",
        "W/\"dep_original.7\"",
        "\"one\", \"two\"",
        " \"one\"",
        "\"one two\"",
        "7",
    ] {
        headers.insert(header::IF_MATCH, HeaderValue::from_str(malformed).unwrap());
        assert_eq!(
            OriginalConfigPrecondition::capture(&headers)
                .require_strong()
                .unwrap_err()
                .status(),
            StatusCode::BAD_REQUEST,
            "{malformed}"
        );
    }
    headers.insert(header::IF_MATCH, wire.clone());
    headers.append(header::IF_MATCH, wire);
    assert_eq!(
        OriginalConfigPrecondition::capture(&headers)
            .require_strong()
            .unwrap_err()
            .status(),
        StatusCode::BAD_REQUEST
    );
}

#[test]
fn answer_round_trip_retains_exact_long_header_and_original_etag() {
    let content_type = format!("application/json; profile=\"{}\"", "x".repeat(300));
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&content_type).unwrap(),
    );
    headers.insert(header::ETAG, HeaderValue::from_static("\"dep_original.7\""));
    let bytes = encode_answer(201, 10, 7, &[9; 32], &headers, b"original reply").unwrap();
    let decoded = decode_answer(&bytes).unwrap();
    assert_eq!(decoded.status, 201);
    assert_eq!(decoded.received_at, 10);
    assert_eq!(decoded.generation, 7);
    assert_eq!(decoded.body, b"original reply");
    let replay = replay(&bytes, &[9; 32]);
    assert_eq!(
        replay.headers()[header::CONTENT_TYPE],
        headers[header::CONTENT_TYPE]
    );
    assert_eq!(replay.headers()[header::ETAG], headers[header::ETAG]);
    assert_eq!(replay.headers()[REPLAYED], "true");
    assert_eq!(
        super::replay(&bytes, &[8; 32]).status(),
        StatusCode::CONFLICT
    );
}

#[test]
fn answer_distinguishes_absent_and_empty_header() {
    let empty = HeaderMap::new();
    let bytes = encode_answer(200, 10, 7, &[9; 32], &empty, b"reply").unwrap();
    assert!(replay(&bytes, &[9; 32])
        .headers()
        .get(header::CONTENT_TYPE)
        .is_none());
    let mut present = empty;
    present.insert(header::CONTENT_TYPE, HeaderValue::from_static(""));
    let bytes = encode_answer(200, 10, 7, &[9; 32], &present, b"reply").unwrap();
    assert_eq!(replay(&bytes, &[9; 32]).headers()[header::CONTENT_TYPE], "");
}

#[test]
fn legacy_answer_has_no_invented_generation_etag() {
    // Exact prior layout 2: status, time, generation, framed digest, u8 type length, type, body.
    let mut bytes = vec![2];
    bytes.extend_from_slice(&200u16.to_be_bytes());
    bytes.extend_from_slice(&10u64.to_be_bytes());
    bytes.extend_from_slice(&7u64.to_be_bytes());
    bytes.extend_from_slice(&[9; 32]);
    bytes.push(16);
    bytes.extend_from_slice(b"application/json");
    bytes.extend_from_slice(b"{}");
    assert_eq!(decode_answer(&bytes).unwrap().body, b"{}");
    let response = replay(&bytes, &[9; 32]);
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(header::ETAG).is_none());
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    bytes[0] = 1;
    assert_eq!(
        replay(&bytes, &[9; 32]).status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[test]
fn malformed_header_layout_is_not_replayed() {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("x"));
    let valid = encode_answer(200, 10, 7, &[9; 32], &headers, b"reply").unwrap();
    for end in 0..58 {
        assert!(decode_answer(&valid[..end]).is_none(), "truncated at {end}");
    }
    let mut bad_marker = valid.clone();
    bad_marker[51] = 2;
    assert!(decode_answer(&bad_marker).is_none());
    let mut bad_length = valid.clone();
    bad_length[52..56].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(decode_answer(&bad_length).is_none());
    let mut bad_value = valid;
    bad_value[56] = b'\n';
    assert!(decode_answer(&bad_value).is_none());
}
