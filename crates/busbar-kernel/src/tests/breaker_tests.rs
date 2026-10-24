// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-kernel/src/breaker.rs`.

use super::*;

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

/// EVERY operator-facing warn/error in the sources this crate took from the retired shared value
/// crate carries a `BUSBAR-NNNN` code — the policy that crate held over its own tree, kept over the
/// same code where it lives now ([`crate::tests::moved_sources`]). (The kernel's own migrated files
/// are held by `diagnostics::tests`'s coverage lint.) This scan makes the next uncoded `warn!` /
/// `error!` (in either spelling) there fail the build rather than quietly drift the docs away from
/// the logs.
///
/// A line is CODED when the emission carries a `diag = ` field — either written through
/// `diag_warn!`/`diag_error!` (which prepend it) or spelled out at a site that branches between
/// warn and debug. The module that DEFINES those macros is the one place the bare macros are
/// legitimately named, so it is excluded.
#[test]
fn test_no_bare_tracing_warn_or_error_in_crate_sources() {
    let mut offenders = Vec::new();
    for rel in crate::tests::moved_sources() {
        if rel.ends_with("diagnostics/mod.rs") {
            continue;
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
        let src = std::fs::read_to_string(&path).expect("read source file");
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.trim_start().starts_with("//") {
                continue; // prose about the macros is not an emission
            }
            // Match both spellings of both macros: a file carrying `use tracing::warn;` and
            // emitting a bare `warn!(…)` is the same uncoded operator-facing log, one import away.
            if !is_bare_log_emission(line) {
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
    assert!(
        offenders.is_empty(),
        "bare tracing::warn!/error! (no BUSBAR-NNNN code) in the moved sources — emit through \
         diag_warn!/diag_error! with a registered Diagnostic:\n{}",
        offenders.join("\n")
    );
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
