// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the contract's status-class vocabulary.

use busbar_contract::upstream::StatusClass;

fn status_class_from_str(s: &str) -> Option<StatusClass> {
    StatusClass::parse(s)
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

/// Every classification the operator's `error_map` may name parses to its class, `billing` and
/// `client_error` included; an unknown word is `None` (no fallback arm). Rehomes
/// the retired engine crate's src/engine/tests/forward_pool_integration_tests.rs::test_status_class_from_str_exhaustive.
#[test]
fn every_error_map_class_word_parses_and_an_unknown_word_does_not() {
    for (word, class) in [
        ("rate_limit", StatusClass::RateLimit),
        ("overloaded", StatusClass::Overloaded),
        ("server_error", StatusClass::ServerError),
        ("timeout", StatusClass::Timeout),
        ("network", StatusClass::Network),
        ("auth", StatusClass::Auth),
        ("billing", StatusClass::Billing),
        ("client_error", StatusClass::ClientError),
    ] {
        assert_eq!(status_class_from_str(word), Some(class), "{word}");
    }
    assert_eq!(status_class_from_str("invalid"), None);
    assert_eq!(status_class_from_str("unknown_code"), None);
}
