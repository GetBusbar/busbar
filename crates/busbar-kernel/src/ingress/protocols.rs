// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Neutral ingress fallbacks. Test registry and codec implementations live in the external kit;
//! a test build can install only the six responses its fixtures supply to these existing calls.
//! A shipping kernel has no registry, executable codec or installation entry point here.

#[cfg(test)]
#[path = "../../../busbar-kernel-testkit/src/ingress/protocols_legacy.rs"]
mod legacy;
#[cfg(test)]
pub use legacy::*;

/// A fixture-rendered response body and its header fields.
#[cfg(any(test, feature = "test-support"))]
pub type ProtocolErrorParts = (serde_json::Value, Vec<(String, Vec<u8>)>);

/// Fixture responses to the kernel's existing neutral fallback calls. This table owns no
/// registry or codec: all state and implementation remain in the caller's test kit.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy)]
pub struct ProtocolTestHooks {
    pub residual_dialect_for_path: fn(&str) -> Option<&'static str>,
    pub residual_default_dialect: fn() -> Option<&'static str>,
    pub vendor_auth_failure_message: fn(&str) -> &'static str,
    pub quota_exceeded_status: fn(&str) -> u16,
    pub auth_failure_status_and_kind: fn(&str) -> (u16, &'static str),
    pub error_parts: fn(&str, u16, &str, &str) -> ProtocolErrorParts,
}

#[cfg(any(test, feature = "test-support"))]
static TEST_HOOKS: std::sync::OnceLock<ProtocolTestHooks> = std::sync::OnceLock::new();

/// Install the process's test-kit responses once. Later registrations update the kit's own
/// registry, which these callbacks read; installing the same table again has no effect.
#[cfg(any(test, feature = "test-support"))]
pub fn install_test_hooks(hooks: ProtocolTestHooks) {
    let _ = TEST_HOOKS.set(hooks);
}

#[cfg(not(test))]
pub fn residual_dialect_for_path(path: &str) -> Option<&'static str> {
    #[cfg(feature = "test-support")]
    if let Some(hooks) = TEST_HOOKS.get() {
        return (hooks.residual_dialect_for_path)(path);
    }
    let _ = path;
    None
}

#[cfg(not(test))]
pub fn residual_default_dialect() -> Option<&'static str> {
    #[cfg(feature = "test-support")]
    if let Some(hooks) = TEST_HOOKS.get() {
        return (hooks.residual_default_dialect)();
    }
    None
}

#[cfg(not(test))]
pub fn vendor_auth_failure_message(proto: &str) -> &'static str {
    #[cfg(feature = "test-support")]
    if let Some(hooks) = TEST_HOOKS.get() {
        return (hooks.vendor_auth_failure_message)(proto);
    }
    let _ = proto;
    "authentication failed"
}

/// The fallback has no dialect-specific quota policy. A door renders its own refusal.
#[cfg(not(test))]
pub fn quota_exceeded_status(proto: &str) -> u16 {
    #[cfg(feature = "test-support")]
    if let Some(hooks) = TEST_HOOKS.get() {
        return (hooks.quota_exceeded_status)(proto);
    }
    let _ = proto;
    429
}

/// The fallback has no dialect-specific authentication policy.
#[cfg(not(test))]
pub fn auth_failure_status_and_kind(proto: &str) -> (u16, &'static str) {
    #[cfg(feature = "test-support")]
    if let Some(hooks) = TEST_HOOKS.get() {
        return (hooks.auth_failure_status_and_kind)(proto);
    }
    let _ = proto;
    (401, busbar_contract::protocol::KIND_AUTHENTICATION)
}

/// Neutral fallback bytes. Shipping requests use their owning door's refusal operation first.
#[cfg(not(test))]
pub fn error_parts(
    proto: &str,
    status: u16,
    kind: &str,
    message: &str,
) -> (serde_json::Value, Vec<(String, Vec<u8>)>) {
    #[cfg(feature = "test-support")]
    if let Some(hooks) = TEST_HOOKS.get() {
        return (hooks.error_parts)(proto, status, kind, message);
    }
    let _ = (proto, status);
    (
        serde_json::json!({ "error": { "message": message, "type": kind } }),
        Vec::new(),
    )
}
