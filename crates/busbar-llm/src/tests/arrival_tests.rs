// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the arrival helpers: the gemini `alt=sse` selector recognizer and the gemini API\n//! version parse. Relocated out of `arrival.rs` per the tests-in-their-own-file convention.

use super::{gemini_api_version, query_has_alt_sse};

/// `query_has_alt_sse` recognizes the gemini SSE selector only as a genuine `alt=sse` pair, not
/// a substring of another param's value, and ignores order / other params. Moved here with the
/// gemini URL-model arrival helper it exercises.
#[test]
fn test_query_has_alt_sse() {
    assert!(query_has_alt_sse("alt=sse"));
    assert!(query_has_alt_sse("key=abc&alt=sse"));
    assert!(query_has_alt_sse("alt=sse&key=abc"));
    assert!(!query_has_alt_sse("alt=json"));
    assert!(!query_has_alt_sse(""));
    // Not fooled by a different param whose VALUE merely contains "alt=sse".
    assert!(!query_has_alt_sse("foo=alt=sse"));
    // `alt` with no value is not the SSE selector.
    assert!(!query_has_alt_sse("alt"));
}

/// Unit: `gemini_api_version` maps each ingress prefix to the token the native error echoes.
#[test]
fn test_gemini_api_version_prefix_mapping() {
    assert_eq!(
        gemini_api_version("/v1/models/foo:countTokens"),
        "v1",
        "stable surface ⇒ v1"
    );
    assert_eq!(
        gemini_api_version("/v1beta/models/foo:countTokens"),
        "v1beta",
        "beta surface ⇒ v1beta"
    );
    // Unexpected shape falls back to the historical default.
    assert_eq!(
        gemini_api_version("/weird/path"),
        "v1beta",
        "fallback ⇒ v1beta"
    );
}
