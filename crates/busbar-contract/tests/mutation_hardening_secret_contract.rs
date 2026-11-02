// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MUTATION-HARDENING: the `busbar_contract::secret` module — `SecretModuleError`/`SecretErrorKind`.

use busbar_contract::secret::{SecretErrorKind, SecretModuleError};

#[test]
fn secret_error_constructors_set_the_matching_kind() {
    assert_eq!(
        SecretModuleError::not_found("x").kind,
        SecretErrorKind::NotFound
    );
    assert_eq!(
        SecretModuleError::unavailable("x").kind,
        SecretErrorKind::Unavailable
    );
    assert_eq!(SecretModuleError::denied("x").kind, SecretErrorKind::Denied);
    assert_eq!(
        SecretModuleError::invalid("x").kind,
        SecretErrorKind::Invalid
    );
    assert_eq!(
        SecretModuleError::internal("x").kind,
        SecretErrorKind::Internal
    );
    assert_eq!(
        SecretModuleError::new(SecretErrorKind::Denied, "y").kind,
        SecretErrorKind::Denied
    );
}

#[test]
fn secret_error_display_carries_kind_and_message() {
    let e = SecretModuleError::not_found("vault path missing");
    let s = e.to_string();
    assert!(s.contains("NotFound"), "{s}");
    assert!(s.contains("vault path missing"), "{s}");
}

/// Every error constructed before the taxonomy existed (a bare-string `?`-conversion) becomes

#[test]
fn secret_error_from_string_and_str_are_internal_kind() {
    let from_string: SecretModuleError = "boom".to_string().into();
    assert_eq!(from_string.kind, SecretErrorKind::Internal);
    assert_eq!(from_string.message, "boom");

    let from_str: SecretModuleError = "boom".into();
    assert_eq!(from_str.kind, SecretErrorKind::Internal);
    assert_eq!(from_str.message, "boom");
}
