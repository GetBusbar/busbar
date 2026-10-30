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

/// Does `line` emit a `warn!`/`error!` log, in EITHER spelling — path-qualified
/// (`tracing::warn!(`) or imported bare (`warn!(`)? A bare `warn!(` must not match the tail of a
/// longer identifier (`diag_warn!(`, `my_error!(`), so the character before it must not be one
/// an identifier can continue with.
fn is_bare_log_emission(line: &str) -> bool {
    ["warn!(", "error!("].iter().any(|macro_name| {
        line.match_indices(macro_name).any(|(at, _)| {
            let before = &line[..at];
            if let Some(stripped) = before.strip_suffix("tracing::") {
                // Path-qualified: `tracing` itself must be a whole path segment.
                return !stripped
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_' || c == ':');
            }
            !before
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_' || c == ':')
        })
    })
}

/// The scan below matched only the PATH-QUALIFIED spelling, so a file carrying `use tracing::warn;`
/// and emitting a bare `warn!(…)` — the same uncoded operator-facing log, one import away — walked
/// straight past it. Pin what the widened matcher does and does not consider an emission.
#[test]
fn the_uncoded_log_scan_matches_both_spellings_of_both_macros() {
    assert!(is_bare_log_emission("    tracing::warn!(\"boom\");"));
    assert!(is_bare_log_emission("    tracing::error!(\"boom\");"));
    // The bare, imported spelling — the gap.
    assert!(is_bare_log_emission("    warn!(\"boom\");"));
    assert!(is_bare_log_emission("    error!(\"boom\");"));
    assert!(is_bare_log_emission("if x { warn!(\"boom\") }"));
    // A longer identifier ENDING in the macro name is not an emission of it.
    assert!(!is_bare_log_emission("    diag_warn!(CODE, \"boom\");"));
    assert!(!is_bare_log_emission("    diag_error!(CODE, \"boom\");"));
    assert!(!is_bare_log_emission("    crate::diag_warn!(CODE, \"x\");"));
    // Neither is an unrelated macro or a plain mention.
    assert!(!is_bare_log_emission("    info!(\"boom\");"));
    assert!(!is_bare_log_emission("    let warn = 1;"));
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
