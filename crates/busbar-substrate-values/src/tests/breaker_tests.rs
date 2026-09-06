// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-substrate/src/breaker.rs`.

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

fn headers_with_retry_after(v: &str) -> http::HeaderMap {
    let mut h = http::HeaderMap::new();
    h.insert(
        http::header::RETRY_AFTER,
        http::HeaderValue::from_str(v).unwrap(),
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
    assert_eq!(parse_retry_after(&http::HeaderMap::new()), None);
}

#[test]
fn status_class_from_str_maps_known_values_and_rejects_unknown() {
    // Every recognised classification round-trips from its wire token; a token the operator's
    // error_map lowered to something UNRECOGNISED yields `None`, which is how the classifier learns
    // an error_map entry points at a class that no longer exists (it then leaves the signal unmapped
    // rather than guessing). Nothing exercised this None arm before.
    assert!(matches!(
        status_class_from_str("rate_limit"),
        Some(StatusClass::RateLimit)
    ));
    assert!(matches!(
        status_class_from_str("overloaded"),
        Some(StatusClass::Overloaded)
    ));
    assert!(matches!(
        status_class_from_str("server_error"),
        Some(StatusClass::ServerError)
    ));
    assert!(matches!(
        status_class_from_str("timeout"),
        Some(StatusClass::Timeout)
    ));
    assert!(matches!(
        status_class_from_str("network"),
        Some(StatusClass::Network)
    ));
    assert!(matches!(
        status_class_from_str("auth"),
        Some(StatusClass::Auth)
    ));
    assert!(status_class_from_str("not_a_class").is_none());
    assert!(status_class_from_str("").is_none());
}

/// The live `error_map` typo warning must carry its registered diagnostic code, not just its text:
/// the catalog documents this exact condition under `CONFIG_ERROR_MAP_CLASS_UNRECOGNIZED`, and an
/// operator greps the code. Two DISTINCT unrecognized values are fed because the dedupe latch is
/// process-global (each value warns at most once for the life of the test binary) and because a
/// warn callsite's interest is cached process-wide — the second emission always follows the rebuilt
/// interest, so the capture is deterministic.
#[test]
fn test_unrecognized_error_map_value_warn_carries_diag_code() {
    use crate::diagnostics::CONFIG_ERROR_MAP_CLASS_UNRECOGNIZED;
    use crate::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;

    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    tracing::subscriber::with_default(subscriber, || {
        for value in ["rate_limt_diagprobe_warm", "rate_limt_diagprobe_assert"] {
            let raw = RawUpstreamError {
                http_status: 503,
                provider_code: Some("probe_code".to_string()),
                structured_type: None,
                retry_after_secs: None,
            };
            let map = err_map(&[("probe_code", value)]);
            let _ = normalize_raw_error(&raw, &map);
        }
    });

    let banner = CONFIG_ERROR_MAP_CLASS_UNRECOGNIZED.banner().to_string();
    assert!(
        cap.contains(&banner),
        "the unrecognized-error_map-value warning must carry diag={banner}; captured: {:?}",
        cap.messages()
    );
    assert!(
        cap.contains("rate_limt_diagprobe_assert"),
        "the offending value stays on the line; captured: {:?}",
        cap.messages()
    );
}

/// EVERY operator-facing warn/error in this crate carries a `BUSBAR-NNNN` code. The diagnostics
/// module states that policy unconditionally; this scan makes the next uncoded `tracing::warn!` /
/// `tracing::error!` fail the build rather than quietly drift the docs away from the logs.
///
/// A line is CODED when the emission carries a `diag = ` field — either written through
/// `diag_warn!`/`diag_error!` (which prepend it) or spelled out at a site that branches between
/// warn and debug. The module that DEFINES those macros is the one place the bare macros are
/// legitimately named, so it is excluded; so are the test-only trees.
#[test]
fn test_no_bare_tracing_warn_or_error_in_crate_sources() {
    fn scan(dir: &std::path::Path, offenders: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("read crate source dir") {
            let path = entry.expect("dir entry").path();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            if path.is_dir() {
                if matches!(name.as_str(), "tests" | "test_support" | "testkit") {
                    continue;
                }
                scan(&path, offenders);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            // The macro definitions themselves, and any co-located test source.
            if path.ends_with("diagnostics/mod.rs") || name.ends_with("_tests.rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("read source file");
            let lines: Vec<&str> = src.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue; // prose about the macros is not an emission
                }
                if !(line.contains("tracing::warn!") || line.contains("tracing::error!")) {
                    continue;
                }
                let coded = line.contains("diag = ")
                    || lines[i + 1..]
                        .iter()
                        .find(|l| !l.trim().is_empty())
                        .is_some_and(|l| l.trim_start().starts_with("diag = "));
                if !coded {
                    offenders.push(format!("{}:{}: {}", path.display(), i + 1, line.trim()));
                }
            }
        }
    }

    let mut offenders = Vec::new();
    scan(
        std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src")),
        &mut offenders,
    );
    assert!(
        offenders.is_empty(),
        "bare tracing::warn!/error! (no BUSBAR-NNNN code) in this crate's sources — emit through \
         diag_warn!/diag_error! with a registered Diagnostic:\n{}",
        offenders.join("\n")
    );
}
