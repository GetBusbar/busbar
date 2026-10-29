// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECRET KIND'S SHARED SOURCE PIECES (`abi::secret`): what every Rust secret source answered
//! alike, stated once.
//!
//! * [`error_kind`] — a [`SecretErrorKind`] as the ABI's `ERROR_KIND_*` code.
//! * [`settings_of`] — a reference's settings bytes as the JSON object they must be.
//! * [`takes_no_settings`] — the instance settings of a source that takes none: empty or `{}`.
//! * [`failed`] — `resolve`'s failure answer: the error's code and its text, FAILED.

use crate::abi::mechanism::call::Outcome;
use crate::abi::sdk::life::Refusal;
use crate::abi::sdk::out::Out;
use crate::abi::secret::{
    ResolveOut, ERROR_KIND_DENIED, ERROR_KIND_INTERNAL, ERROR_KIND_INVALID, ERROR_KIND_NOT_FOUND,
    ERROR_KIND_UNAVAILABLE,
};
use crate::secret::{SecretErrorKind, SecretModuleError, SecretResult};

/// The `abi::secret::ERROR_KIND_*` code of a [`SecretErrorKind`].
#[must_use]
pub const fn error_kind(kind: SecretErrorKind) -> u32 {
    match kind {
        SecretErrorKind::NotFound => ERROR_KIND_NOT_FOUND,
        SecretErrorKind::Unavailable => ERROR_KIND_UNAVAILABLE,
        SecretErrorKind::Denied => ERROR_KIND_DENIED,
        SecretErrorKind::Invalid => ERROR_KIND_INVALID,
        SecretErrorKind::Internal => ERROR_KIND_INTERNAL,
    }
}

/// A resolve's settings bytes as the JSON object they must be (empty = none).
///
/// # Errors
/// [`SecretErrorKind::Invalid`]: the bytes are not a JSON object.
pub fn settings_of(bytes: &[u8]) -> SecretResult<serde_json::Map<String, serde_json::Value>> {
    if bytes.is_empty() {
        return Ok(serde_json::Map::new());
    }
    serde_json::from_slice(bytes).map_err(|e| {
        SecretModuleError::invalid(format!("secret settings are not a JSON object: {e}"))
    })
}

/// The instance settings of the source `module`, which takes none: empty bytes or an empty object.
/// Anything else is refused naming why; `names` says where a reference names its value instead
/// (`"variable in its own settings.key"`).
///
/// # Errors
/// The settings are not a JSON object, or name a setting.
pub fn takes_no_settings(bytes: &[u8], module: &str, names: &str) -> Result<(), String> {
    if bytes.is_empty() {
        return Ok(());
    }
    match serde_json::from_slice::<serde_json::Value>(bytes) {
        Ok(serde_json::Value::Object(m)) => match m.keys().next() {
            None => Ok(()),
            Some(k) => Err(format!(
                "secret module '{module}' takes no settings; remove settings.{k} (each reference \
                 names its {names})"
            )),
        },
        _ => Err("settings: must be a JSON object".to_string()),
    }
}

/// `resolve`'s failure answer: `e`'s code in `error_kind`, its text, FAILED.
pub fn failed(out: &mut Out<'_, ResolveOut>, e: SecretModuleError) -> Outcome {
    out.set(|o| &o.error_kind, error_kind(e.kind));
    out.fail(Refusal::failed(e.message))
}

#[cfg(test)]
#[path = "tests/secret_tests.rs"]
mod tests;
