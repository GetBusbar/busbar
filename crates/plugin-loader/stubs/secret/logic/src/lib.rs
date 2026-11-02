// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![forbid(unsafe_code)]

use busbar_contract::abi::sdk::cred::Held;
use busbar_contract::abi::secret::{
    ERROR_KIND_DENIED, ERROR_KIND_INTERNAL, ERROR_KIND_INVALID, ERROR_KIND_NOT_FOUND,
    ERROR_KIND_UNAVAILABLE,
};
use busbar_contract::secret::{SecretErrorKind, SecretModuleError, SecretResult};

pub mod door;

pub const WORD: &str = "env";

pub const KEY: &str = "key";

pub const NAME: &str = "busbar-stub-secret";

pub fn resolve(
    settings: &serde_json::Map<String, serde_json::Value>,
) -> SecretResult<Held<Vec<u8>>> {
    let var = match settings.get(KEY).and_then(|v| v.as_str()) {
        Some(v) if !v.trim().is_empty() => v,
        _ => {
            return Err(SecretModuleError::invalid(
                "secret module 'env' requires settings.key naming the environment variable \
                 (e.g. `{ env: MY_VAR }` or `{ module: env, settings: { key: MY_VAR } }`)",
            ))
        }
    };

    let unset = || {
        SecretModuleError::not_found(format!(
            "secret env:{var} cannot resolve: environment variable '{var}' is unset"
        ))
    };
    let Some(value) = std::env::var_os(var) else {
        return Err(unset());
    };
    let bytes = value.into_encoded_bytes();
    let text = std::str::from_utf8(&bytes).is_ok();
    let held = Held::new(bytes);
    if !text {
        return Err(unset());
    }
    if held.is_empty() {
        return Err(SecretModuleError::invalid(format!(
            "secret env:{var} resolved to an EMPTY value; a secret must be non-empty \
             (fail-closed)"
        )));
    }
    Ok(held)
}

pub fn settings_of(bytes: &[u8]) -> SecretResult<serde_json::Map<String, serde_json::Value>> {
    if bytes.is_empty() {
        return Ok(serde_json::Map::new());
    }
    serde_json::from_slice(bytes).map_err(|e| {
        SecretModuleError::invalid(format!("secret settings are not a JSON object: {e}"))
    })
}

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
