// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::redacted::Secret;

#[test]
fn resolver_retains_raw_bytes_and_trims_the_text_view() {
    let reference = fixed_reference("raw-text-source");
    let r = fixed_value("raw-text-source", b"abc\n");
    assert_eq!(
        r.resolve(&reference).unwrap(),
        Secret::new(b"abc\n".to_vec())
    );
    assert_eq!(
        r.resolve_string(&reference).unwrap(),
        Secret::new("abc".to_string())
    );
}

#[test]
fn resolver_unknown_module_without_plugin_fails_closed() {
    let r = SecretResolver::builtins_only();
    let err = r.resolve(&fixed_reference("unknown-source")).unwrap_err();
    assert!(
        err.contains("unknown-source") && err.contains("fail-closed"),
        "unknown module with no plugin refuses: {err}"
    );
}

#[test]
fn resolver_delegates_to_plugin_and_fails_closed_on_empty_or_error() {
    let r = fixed_resolver(vec![
        (
            fixed_reference("source-ok"),
            Ok(Secret::new(b"plugin-secret".to_vec())),
        ),
        (fixed_reference("source-empty"), Ok(Secret::new(Vec::new()))),
        (
            fixed_reference("second-source"),
            Ok(Secret::new(b"second-value".to_vec())),
        ),
    ]);
    assert_eq!(
        r.resolve(&fixed_reference("source-ok")).unwrap(),
        Secret::new(b"plugin-secret".to_vec())
    );
    assert!(r
        .resolve(&fixed_reference("source-empty"))
        .unwrap_err()
        .contains("EMPTY"));
    assert!(r
        .resolve(&fixed_reference("source-missing"))
        .unwrap_err()
        .contains("failed to resolve"));
    assert_eq!(
        r.resolve_string(&fixed_reference("second-source")).unwrap(),
        Secret::new("second-value".to_string())
    );
}
