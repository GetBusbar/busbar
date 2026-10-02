// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MUTATION-HARDENING: the `busbar_contract::secret` module — `SecretModuleError`/`SecretErrorKind`
//! and `SecretModule`'s defaulted `resolve_with_deadline`.
//!
//! Moved here from `busbar-api`'s own suite when that crate retired; the built-in `env`/`file`
//! resolvers' half of that suite moved with them to the plugin loader
//! (`crates/plugin-loader/tests/builtin_secret_hardening.rs`). Integration test — public-surface
//! only, same convention as `mutation_hardening_record_store.rs` in this same directory.

use busbar_contract::secret::{SecretErrorKind, SecretModule, SecretModuleError, SecretResult};
use std::sync::atomic::Ordering;

// ── `SecretErrorKind` / `SecretModuleError` construction + Display ─────────────────────────────────────

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
/// `Internal` — behaviorally identical to the untyped predecessor, just now typed. Pinning BOTH
/// `From` impls separately: nothing here says `From<&str>` must delegate to `From<String>` (or vice
/// versa), so a mutant that broke one but not the other needs both covered.
#[test]
fn secret_error_from_string_and_str_are_internal_kind() {
    let from_string: SecretModuleError = "boom".to_string().into();
    assert_eq!(from_string.kind, SecretErrorKind::Internal);
    assert_eq!(from_string.message, "boom");

    let from_str: SecretModuleError = "boom".into();
    assert_eq!(from_str.kind, SecretErrorKind::Internal);
    assert_eq!(from_str.message, "boom");
}

// ── `SecretModule::resolve_with_deadline` DEFAULT — forwards to `resolve`, ignores the deadline ──

struct RecordingModule {
    calls: std::sync::atomic::AtomicUsize,
}

impl SecretModule for RecordingModule {
    fn resolve(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
    ) -> SecretResult<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match settings.get("v").and_then(|v| v.as_str()) {
            Some(v) => Ok(v.as_bytes().to_vec()),
            None => Err(SecretModuleError::invalid("missing v")),
        }
    }
}

#[test]
fn resolve_with_deadline_default_forwards_to_resolve_and_ignores_deadline() {
    let m = RecordingModule {
        calls: Default::default(),
    };
    let mut settings = serde_json::Map::new();
    settings.insert("v".to_string(), serde_json::Value::String("hi".into()));

    // With a deadline...
    let got = m.resolve_with_deadline(&settings, Some(50)).unwrap();
    assert_eq!(got, b"hi");
    // ...and with none — both reach the same underlying `resolve`.
    let got = m.resolve_with_deadline(&settings, None).unwrap();
    assert_eq!(got, b"hi");
    assert_eq!(m.calls.load(Ordering::SeqCst), 2);

    // The error path forwards too, unmodified.
    let empty = serde_json::Map::new();
    let err = m.resolve_with_deadline(&empty, Some(1)).unwrap_err();
    assert_eq!(err.kind, SecretErrorKind::Invalid);
}
