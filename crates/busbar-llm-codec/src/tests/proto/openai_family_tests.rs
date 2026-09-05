// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/proto/openai_family.rs`.

use busbar_substrate_values::breaker::StatusClass;
use http::StatusCode;

#[test]
fn test_openai_classify() {
    let protocol = crate::proto_codec::protocol_for("openai").expect("openai should exist");
    let reader = protocol.reader();

    // Test 429 → RateLimit
    let signal = reader.classify(StatusCode::TOO_MANY_REQUESTS, b"{}");
    assert_eq!(signal.class, StatusClass::RateLimit);

    // Test 401 → Auth
    let signal = reader.classify(StatusCode::UNAUTHORIZED, b"{}");
    assert_eq!(signal.class, StatusClass::Auth);

    // Test 503 → ServerError
    let signal = reader.classify(StatusCode::SERVICE_UNAVAILABLE, b"{}");
    assert_eq!(signal.class, StatusClass::ServerError);

    // Test 403 → Auth
    let signal = reader.classify(StatusCode::FORBIDDEN, b"{}");
    assert_eq!(signal.class, StatusClass::Auth);
}

/// The shared context-length prose scan must fire on the canonical self-contained phrases and on
/// the `exceeds`+`context`/`token limit` pairing — this is what lets a genuine oversized-request
/// body fail over (to a larger-context model) instead of penalizing the lane's breaker.
#[test]
fn context_length_prose_scan_fires_on_canonical_phrases() {
    use super::openai_context_length_prose_scan as scan;
    // Caller lowercases before calling; assert on already-lowercased inputs.
    assert!(scan("this model's maximum context length is 8192 tokens"));
    assert!(scan("context length exceeded for this request"));
    assert!(scan("please reduce the length of the messages"));
    // `exceeds` must be CO-LOCATED with context/token-limit to count.
    assert!(scan("your input exceeds the context window"));
    assert!(scan("the request exceeds the token limit"));
}

/// Precision guard: the scan must NOT fire on unrelated errors whose prose merely mentions weak
/// tokens like `token`/`maximum` — e.g. a per-day quota (rate-limit) body — or a bare `exceeds`
/// with no context/token-limit co-location. Misclassifying these as context-length would let a
/// real rate-limit/quota failure escape breaker penalty by "failing over" instead.
#[test]
fn context_length_prose_scan_precise_no_false_positive() {
    use super::openai_context_length_prose_scan as scan;
    assert!(
        !scan("you have reached the maximum number of tokens allowed per day"),
        "a per-day quota body is a rate-limit, not context-length"
    );
    assert!(
        !scan("the request exceeds your monthly spend limit"),
        "`exceeds` without context/token-limit co-location must not fire"
    );
    assert!(!scan("invalid api key provided"));
    assert!(!scan(""));
}

/// `bearer_error_code` mirrors the native OpenAI `type`→`code` pairing: only auth and
/// insufficient-quota carry a machine-readable `code` (the value official SDKs surface as
/// `error.code`); every other modeled type — and any passthrough type — stays `null`, matching
/// the shape OpenAI uses when no code applies. Emitting a spurious code is a proxy tell.
#[test]
fn bearer_error_code_mirrors_native_type_code_pairing() {
    use super::bearer_error_code as code;
    assert_eq!(
        code(busbar_substrate_values::proxy::KIND_AUTHENTICATION),
        serde_json::Value::String("invalid_api_key".to_string())
    );
    assert_eq!(
        code(busbar_substrate_values::proxy::KIND_INSUFFICIENT_QUOTA),
        serde_json::Value::String("insufficient_quota".to_string())
    );
    // Every modeled non-auth/non-quota type carries no code.
    for t in [
        busbar_substrate_values::proxy::KIND_INVALID_REQUEST,
        busbar_substrate_values::proxy::KIND_PERMISSION,
        busbar_substrate_values::proxy::KIND_NOT_FOUND,
        busbar_substrate_values::proxy::KIND_RATE_LIMIT,
        busbar_substrate_values::proxy::KIND_SERVER_ERROR,
        busbar_substrate_values::proxy::KIND_API_ERROR,
    ] {
        assert_eq!(code(t), serde_json::Value::Null, "{t} must emit code:null");
    }
    // An unmodeled passthrough type also stays null (native shape), never invents a code.
    assert_eq!(code("some_future_error_type"), serde_json::Value::Null);
}
