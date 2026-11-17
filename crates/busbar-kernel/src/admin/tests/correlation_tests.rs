// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ADMIN-API-1.6-ONE-MODEL section 7: what the engine keeps of a caller's correlation.

use super::*;
use axum::http::{HeaderMap, HeaderValue};

const TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const PARENT: &str = "00f067aa0ba902b7";

#[test]
fn a_client_request_id_is_kept_only_when_valid() {
    for valid in ["a", "console-req.1:a_b-c", "x".repeat(128).as_str()] {
        assert!(valid_client_request_id(valid.as_bytes()), "{valid}");
    }
    for invalid in [
        "",
        "has space",
        "slash/no",
        "é",
        "x".repeat(129).as_str(),
        "tab\t",
    ] {
        assert!(!valid_client_request_id(invalid.as_bytes()), "{invalid:?}");
    }
}

#[test]
fn traceparent_reads_w3c_level_1() {
    let parsed = TraceParent::parse(&format!("00-{TRACE}-{PARENT}-01")).expect("valid");
    assert_eq!(parsed.trace_id, TRACE);
    assert_eq!(parsed.parent_id, PARENT);
    assert_eq!(parsed.flags, "01");
    assert!(
        TraceParent::parse(&format!("cc-{TRACE}-{PARENT}-01-future")).is_some(),
        "a later version is read by its first four fields"
    );
    for refused in [
        format!("00-{TRACE}-{PARENT}-01-extra"),
        format!("ff-{TRACE}-{PARENT}-01"),
        format!("00-{}-{PARENT}-01", "0".repeat(32)),
        format!("00-{TRACE}-{}-01", "0".repeat(16)),
        format!("00-{}-{PARENT}-01", TRACE.to_uppercase()),
        format!("00-{TRACE}-{PARENT}-1"),
        format!("cc-{TRACE}-{PARENT}-01x"),
        "00-short".to_string(),
        String::new(),
    ] {
        assert!(TraceParent::parse(&refused).is_none(), "{refused:?}");
    }
    assert_eq!(
        parsed.child(&[0xab; 8]),
        format!("00-{TRACE}-abababababababab-01"),
        "the answer keeps the trace and flags and names the admin span"
    );
}

#[test]
fn correlation_reads_single_headers_and_answers_them() {
    let mut headers = HeaderMap::new();
    headers.insert(HEADER_REQUEST_ID, HeaderValue::from_static("cli-1"));
    headers.insert(
        HEADER_TRACEPARENT,
        HeaderValue::from_str(&format!("00-{TRACE}-{PARENT}-00")).unwrap(),
    );
    let correlation = Correlation::of(&headers);
    assert_eq!(correlation.client_request_id.as_deref(), Some("cli-1"));
    assert_eq!(
        correlation.trace.as_ref().map(|t| t.trace_id.as_str()),
        Some(TRACE)
    );

    let mut answer = HeaderMap::new();
    correlation.answer(Some(&[1; 8]), &mut answer);
    assert_eq!(answer[HEADER_CLIENT_REQUEST_ID], "cli-1");
    assert_eq!(
        answer[HEADER_TRACEPARENT],
        format!("00-{TRACE}-0101010101010101-00").as_str()
    );
    let mut unspanned = HeaderMap::new();
    correlation.answer(None, &mut unspanned);
    assert!(
        !unspanned.contains_key(HEADER_TRACEPARENT),
        "no admin span id, no traceparent"
    );

    let mut twice = HeaderMap::new();
    twice.append(HEADER_REQUEST_ID, HeaderValue::from_static("one"));
    twice.append(HEADER_REQUEST_ID, HeaderValue::from_static("two"));
    twice.insert(HEADER_TRACEPARENT, HeaderValue::from_static("garbage"));
    let dropped = Correlation::of(&twice);
    assert_eq!(
        dropped,
        Correlation::default(),
        "repeated or invalid values are dropped"
    );
    let mut silent = HeaderMap::new();
    dropped.answer(Some(&[1; 8]), &mut silent);
    assert!(
        silent.is_empty(),
        "nothing is answered for what was dropped"
    );
}
