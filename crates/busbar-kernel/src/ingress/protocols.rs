// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Compatibility for the former Rust protocol registry. Production planes describe their routes
//! and render their refusals through the memory ABI. Executable codec declarations are available
//! only to legacy fixtures; a shipping kernel cannot install or call one.

#[cfg(any(test, feature = "test-support"))]
#[path = "protocols_legacy.rs"]
mod legacy;
#[cfg(any(test, feature = "test-support"))]
pub use legacy::*;

#[cfg(not(any(test, feature = "test-support")))]
pub fn residual_dialect_for_path(_path: &str) -> Option<&'static str> {
    None
}

#[cfg(not(any(test, feature = "test-support")))]
pub fn residual_default_dialect() -> Option<&'static str> {
    None
}

#[cfg(not(any(test, feature = "test-support")))]
pub fn vendor_auth_failure_message(_proto: &str) -> &'static str {
    "authentication failed"
}

/// The fallback has no dialect-specific quota policy. A door renders its own refusal.
pub fn quota_exceeded_status(proto: &str) -> u16 {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(decl) = decl_for(proto) {
        return decl.quota_exceeded_status;
    }
    let _ = proto;
    429
}

/// The fallback has no dialect-specific authentication policy.
pub fn auth_failure_status_and_kind(proto: &str) -> (u16, &'static str) {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(decl) = decl_for(proto) {
        return decl.auth_failure_status_and_kind;
    }
    let _ = proto;
    (401, busbar_contract::protocol::KIND_AUTHENTICATION)
}

/// Neutral fallback bytes. Legacy fixtures may exercise a codec directly; shipping requests use
/// their owning door's refusal operation before reaching this fallback.
pub fn error_parts(
    proto: &str,
    status: u16,
    kind: &str,
    message: &str,
) -> (serde_json::Value, Vec<(String, Vec<u8>)>) {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(dialect) = decl_for(proto).and_then(|decl| decl.dialect()) {
        let envelope = dialect.write_error(CODEC_HOST, status, kind, message);
        let fields = dialect.error_response_fields(CODEC_HOST, kind, &envelope);
        return (envelope, fields);
    }
    let _ = (proto, status);
    (
        serde_json::json!({ "error": { "message": message, "type": kind } }),
        Vec::new(),
    )
}
