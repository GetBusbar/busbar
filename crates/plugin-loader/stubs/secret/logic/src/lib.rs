// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `env` SECRET SOURCE for busbar's `kind: secret` plugin family, on the secret kind's memory
//! ABI (`busbar_contract::abi::secret`). This crate is the LOGIC and its door ([`door::door`]); the
//! dropped-in `cdylib` is the sibling `busbar-secret-env-plugin` crate, which exports the same door
//! as `busbar_plugin_door`.
//!
//! `resolve` reads the environment variable its settings' `key` names. `{ env: VAR }` is the
//! reference sugar for `{ module: env, settings: { key: VAR } }`.
//!
//! It is an ordinary plugin (THE DESIGN §2): linked in the default build or dropped in, called
//! through the secret kind table by the one dispatcher, and loaded only when a reference names it.
//! Every refusal of a variable or its `key` is 1.5.5's, byte for byte (`is unset`, `EMPTY value`,
//! `requires settings.key`). The one other refusal, settings bytes that are not a JSON object, is the
//! secret kind's ABI shape, which 1.5.5's in-process source never received. None carries the value.

#![forbid(unsafe_code)]

use busbar_contract::abi::secret::{
    ERROR_KIND_DENIED, ERROR_KIND_INTERNAL, ERROR_KIND_INVALID, ERROR_KIND_NOT_FOUND,
    ERROR_KIND_UNAVAILABLE,
};
use busbar_contract::secret::{SecretErrorKind, SecretModuleError, SecretResult};

pub mod door;

/// The word config names this source by: its module alias and its reference sugar
/// (`{ env: X }`), spelled here, never by the contract.
pub const WORD: &str = "env";

/// The settings key the sugar's value lands under (`{ env: X }` → `settings.key`).
pub const KEY: &str = "key";

/// The plugin's name (the manifest name).
pub const NAME: &str = "busbar-stub-secret";

/// Resolve `settings` (`{ key: VAR }`) to the variable's value, byte for byte.
///
/// # Errors
/// Fail-closed, as 1.5.5: an unset or non-UTF-8 variable (both "is unset") and an empty one are
/// refused, and so is a missing or blank `key`. The text names the variable, never its value.
pub fn resolve(settings: &serde_json::Map<String, serde_json::Value>) -> SecretResult<Vec<u8>> {
    let var = match settings.get(KEY).and_then(|v| v.as_str()) {
        Some(v) if !v.trim().is_empty() => v,
        _ => {
            return Err(SecretModuleError::invalid(
                "secret module 'env' requires settings.key naming the environment variable \
                 (e.g. `{ env: MY_VAR }` or `{ module: env, settings: { key: MY_VAR } }`)",
            ))
        }
    };
    // 1.5.5's reading, byte for byte (v1.5.5 crates/busbar/src/config/secret.rs `resolve_builtin`):
    // `std::env::var`, whose one `Err` covers a variable that is absent and one whose value is not
    // UTF-8, both answered "is unset"; an EMPTY value refused; any other value, a whitespace-only
    // one included, resolved untrimmed. The value is never quoted back.
    match std::env::var(var) {
        Ok(v) if !v.is_empty() => Ok(v.into_bytes()),
        Ok(_) => Err(SecretModuleError::invalid(format!(
            "secret env:{var} resolved to an EMPTY value; a secret must be non-empty \
             (fail-closed)"
        ))),
        Err(_) => Err(SecretModuleError::not_found(format!(
            "secret env:{var} cannot resolve: environment variable '{var}' is unset"
        ))),
    }
}

/// A resolve's settings bytes as the JSON object they must be (empty = none).
///
/// # Errors
/// The bytes are not a JSON object.
pub fn settings_of(bytes: &[u8]) -> SecretResult<serde_json::Map<String, serde_json::Value>> {
    if bytes.is_empty() {
        return Ok(serde_json::Map::new());
    }
    serde_json::from_slice(bytes).map_err(|e| {
        SecretModuleError::invalid(format!("secret settings are not a JSON object: {e}"))
    })
}

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
