// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/breaker.rs`.

use super::*;
use std::collections::HashMap;

fn err_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn test_structured_type_drives_error_map() {
    // No provider code, but a structured error type the operator mapped to `overloaded`.
    let raw = RawUpstreamError {
        http_status: 400, // would otherwise classify as ClientError
        provider_code: None,
        structured_type: Some("model_overloaded".to_string()),
        retry_after_secs: None,
    };
    let map = err_map(&[("model_overloaded", "overloaded")]);
    let sig = normalize_raw_error(&raw, &map);
    assert_eq!(sig.class, StatusClass::Overloaded);
    assert_eq!(sig.provider_signal.as_deref(), Some("model_overloaded"));
}

#[test]
fn test_provider_code_wins_over_structured_type() {
    let raw = RawUpstreamError {
        http_status: 500,
        provider_code: Some("1302".to_string()),
        structured_type: Some("server_error".to_string()),
        retry_after_secs: None,
    };
    // Both mapped; the explicit code takes precedence.
    let map = err_map(&[("1302", "rate_limit"), ("server_error", "server_error")]);
    let sig = normalize_raw_error(&raw, &map);
    assert_eq!(sig.class, StatusClass::RateLimit);
}

#[test]
fn test_builtin_context_length_on_real_400_classifies_context_length() {
    // A genuine 400 carrying the canonical context-length code is ContextLength: the lane is
    // healthy, fail over without penalizing the breaker.
    let raw = RawUpstreamError {
        http_status: 400,
        provider_code: Some(crate::proxy::PROVIDER_CODE_CONTEXT_LENGTH.to_string()),
        structured_type: None,
        retry_after_secs: None,
    };
    let sig = normalize_raw_error(&raw, &HashMap::new());
    assert_eq!(sig.class, StatusClass::ContextLength);
    assert_eq!(
        sig.provider_signal.as_deref(),
        Some("context_length_exceeded") // golden wire-contract literal (kept bare on purpose)
    );
}

#[test]
fn test_builtin_context_length_not_recognized_on_5xx() {
    // A 5xx is a real upstream server failure, never a context-length error. Even if the body
    // happens to carry a `context_length_exceeded` code, it must classify as ServerError (→
    // TransientUpstream) so the breaker is penalized — NOT ContextLength.
    let raw = RawUpstreamError {
        http_status: 503,
        provider_code: Some(crate::proxy::PROVIDER_CODE_CONTEXT_LENGTH.to_string()),
        structured_type: None,
        retry_after_secs: None,
    };
    let sig = normalize_raw_error(&raw, &HashMap::new());
    assert_eq!(sig.class, StatusClass::ServerError);
}

#[test]
fn test_operator_error_map_overrides_builtin_context_length() {
    // The operator error_map is checked first and returns early, so it countermands the
    // built-in context-length recognition even for the canonical code on a 400.
    let raw = RawUpstreamError {
        http_status: 400,
        provider_code: Some(crate::proxy::PROVIDER_CODE_CONTEXT_LENGTH.to_string()),
        structured_type: None,
        retry_after_secs: None,
    };
    let map = err_map(&[(crate::proxy::PROVIDER_CODE_CONTEXT_LENGTH, "client_error")]);
    let sig = normalize_raw_error(&raw, &map);
    assert_eq!(sig.class, StatusClass::ClientError);
}

#[test]
fn test_operator_map_context_length_on_5xx_is_penalized() {
    // Regression: an operator error_map mapping a provider code to
    // `context_length` on a 503 must NOT mask the upstream outage. The early return is
    // suppressed and we fall through to HTTP-status classification → ServerError
    // (TransientUpstream), so the breaker is penalized.
    let raw = RawUpstreamError {
        http_status: 503,
        provider_code: Some("1234".to_string()),
        structured_type: None,
        retry_after_secs: None,
    };
    let map = err_map(&[("1234", "context_length")]);
    let sig = normalize_raw_error(&raw, &map);
    assert_eq!(sig.class, StatusClass::ServerError);
    assert_eq!(classify(&sig), Disposition::TransientUpstream);
}

#[test]
fn test_operator_map_context_length_on_400_still_classifies_context_length() {
    // Companion to the 5xx case: a genuine request-size 400 mapped to `context_length`
    // still resolves to ContextLength (fail over without penalty). The guard only fires
    // on 5xx.
    let raw = RawUpstreamError {
        http_status: 400,
        provider_code: Some("1234".to_string()),
        structured_type: None,
        retry_after_secs: None,
    };
    let map = err_map(&[("1234", "context_length")]);
    let sig = normalize_raw_error(&raw, &map);
    assert_eq!(sig.class, StatusClass::ContextLength);
}

#[test]
fn test_structured_type_context_length_on_5xx_is_penalized() {
    // Same CLASS guard on the structured-type path: a typed signal mapped to
    // `context_length` on a 502 must fall through to ServerError, not mask the outage.
    let raw = RawUpstreamError {
        http_status: 502,
        provider_code: None,
        structured_type: Some("ctx_overflow".to_string()),
        retry_after_secs: None,
    };
    let map = err_map(&[("ctx_overflow", "context_length")]);
    let sig = normalize_raw_error(&raw, &map);
    assert_eq!(sig.class, StatusClass::ServerError);
    assert_eq!(classify(&sig), Disposition::TransientUpstream);
}

#[test]
fn test_builtin_context_length_not_recognized_on_non_request_size_4xx() {
    // Tighten regression: the built-in context_length code only applies to the
    // oversized-request statuses (400/413). A 403 carrying the canonical code must NOT be
    // reclassified as ContextLength; it falls through to HTTP classification (Auth here).
    // A guard of merely `!(500..600)` would wrongly accept any non-5xx.
    let raw = RawUpstreamError {
        http_status: 403,
        provider_code: Some(crate::proxy::PROVIDER_CODE_CONTEXT_LENGTH.to_string()),
        structured_type: None,
        retry_after_secs: None,
    };
    let sig = normalize_raw_error(&raw, &HashMap::new());
    assert_eq!(sig.class, StatusClass::Auth);
}

#[test]
fn test_builtin_context_length_recognized_on_413() {
    // 413 Payload Too Large is the other oversized-request status the tightened guard
    // accepts for the built-in context_length code.
    let raw = RawUpstreamError {
        http_status: 413,
        provider_code: Some(crate::proxy::PROVIDER_CODE_CONTEXT_LENGTH.to_string()),
        structured_type: None,
        retry_after_secs: None,
    };
    let sig = normalize_raw_error(&raw, &HashMap::new());
    assert_eq!(sig.class, StatusClass::ContextLength);
}

#[test]
fn test_unmapped_structured_type_falls_through_to_http() {
    let raw = RawUpstreamError {
        http_status: 429,
        provider_code: None,
        structured_type: Some("something_unmapped".to_string()),
        retry_after_secs: None,
    };
    let sig = normalize_raw_error(&raw, &HashMap::new());
    assert_eq!(sig.class, StatusClass::RateLimit); // from HTTP 429
}

fn headers_with_retry_after(v: &str) -> axum::http::HeaderMap {
    let mut h = axum::http::HeaderMap::new();
    h.insert(
        axum::http::header::RETRY_AFTER,
        axum::http::HeaderValue::from_str(v).unwrap(),
    );
    h
}

#[test]
fn retry_after_accepts_the_http_date_form() {
    let at = std::time::SystemTime::now() + std::time::Duration::from_secs(120);
    let date = httpdate::fmt_http_date(at);
    let secs = parse_retry_after(&headers_with_retry_after(&date));
    let n = secs.expect("HTTP-date Retry-After must parse");
    assert!((115..=120).contains(&n), "got {n}");
}

#[test]
fn retry_after_accepts_delay_seconds() {
    // Regression proof: passes before and after — the integer form already worked.
    assert_eq!(
        parse_retry_after(&headers_with_retry_after("120")),
        Some(120)
    );
}

#[test]
fn a_past_http_date_retry_after_floors_at_zero() {
    let at = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    let date = httpdate::fmt_http_date(at);
    assert_eq!(parse_retry_after(&headers_with_retry_after(&date)), Some(0));
}

#[test]
fn a_missing_retry_after_is_none() {
    assert_eq!(parse_retry_after(&axum::http::HeaderMap::new()), None);
}
