// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECRET DOUBLE: the kernel's own secret port — the contract's [`SecretAxis`] /
//! [`SecretCalls`], the seam the composition root installs and the kernel names nothing behind —
//! answered in process, so the kernel's tests resolve `{ env: VAR }` / `{ file: PATH }` references
//! with no secret plugin linked (ARCHITECT R-FIX3, 2026-09-26: a behaviour double the kernel's own
//! tests need lives in-crate, linked only). It is not a plugin, not a door and not a copy of one:
//! its refusal words are its own, so a kernel test that pins a rendered refusal pins the kernel's
//! passing of a module's text through verbatim, never a plugin's wording. The shipped `env` / `file`
//! plugins' own behaviour and their 1.5.5 words are proven where they are linked, at the
//! composition root (`crates/busbar/src/root/tests/linked_secret_sources.rs` and
//! `root/tests/linked.rs`).
//!
//! It answers by the two module aliases the contract names ([`SECRET_MODULE_ENV`],
//! [`SECRET_MODULE_FILE`]) and honours what the contract asks of every secret module
//! ([`busbar_contract::secret::SecretModule::resolve`]): fail-closed on a missing setting, a missing
//! source and an empty value, and a refusal text that names the source, never the value. A value it
//! returns is the source's bytes, untouched. Beyond that it does nothing a plugin does on its own
//! account (no regular-file check, no size cap, no blank rule): what the kernel does with a value or
//! a refusal is what the kernel's tests prove.
//!
//! - `env` reads the variable `settings.key` names: unset is `NotFound`; set but not UTF-8, or
//!   empty, is `Invalid`.
//! - `file` reads the file `settings.path` names: an I/O failure is `NotFound` when nothing is
//!   there and `Unavailable` otherwise; an empty file is `Invalid`.
//! - A settings document that is not a JSON object, or a missing / blank `key` / `path`, is
//!   `Invalid`.

use std::sync::Arc;

use busbar_contract::abi::secret::{
    ERROR_KIND_INVALID, ERROR_KIND_NOT_FOUND, ERROR_KIND_UNAVAILABLE,
};
use busbar_contract::redacted::Redacted;
use busbar_contract::secret::{SecretAxis, SecretCalls, SecretRefused};
use busbar_contract::secret_ref::{
    SecretRef, SECRET_ENV_SETTING_KEY, SECRET_FILE_SETTING_PATH, SECRET_MODULE_ENV,
    SECRET_MODULE_FILE,
};

/// The stand-in secret axis a test build installs in place of the root's (`preflight::STAND_IN`).
pub struct SecretsStandIn;

/// Which of the two sources a reference names.
#[derive(Clone, Copy)]
enum Double {
    Env,
    File,
}

fn double(module: &str) -> Option<Double> {
    match module {
        SECRET_MODULE_ENV => Some(Double::Env),
        SECRET_MODULE_FILE => Some(Double::File),
        _ => None,
    }
}

fn refused(error_kind: u32, text: String) -> SecretRefused {
    SecretRefused { error_kind, text }
}

/// The non-blank string setting `field` of a settings document.
fn setting(settings: &[u8], module: &str, field: &str) -> Result<String, SecretRefused> {
    let doc: serde_json::Map<String, serde_json::Value> = if settings.is_empty() {
        serde_json::Map::new()
    } else {
        serde_json::from_slice(settings).map_err(|e| {
            refused(
                ERROR_KIND_INVALID,
                format!("secret double ({module}): settings are not a JSON object: {e}"),
            )
        })?
    };
    match doc.get(field).and_then(|v| v.as_str()) {
        Some(v) if !v.trim().is_empty() => Ok(v.to_string()),
        _ => Err(refused(
            ERROR_KIND_INVALID,
            format!("secret double ({module}): settings.{field} is missing or blank"),
        )),
    }
}

fn resolve_env(settings: &[u8]) -> Result<Vec<u8>, SecretRefused> {
    let var = setting(settings, SECRET_MODULE_ENV, SECRET_ENV_SETTING_KEY)?;
    let Some(raw) = std::env::var_os(&var) else {
        return Err(refused(
            ERROR_KIND_NOT_FOUND,
            format!("secret double (env): variable {var} is unset"),
        ));
    };
    let value = raw.into_string().map_err(|_| {
        refused(
            ERROR_KIND_INVALID,
            format!("secret double (env): variable {var} is set but not UTF-8"),
        )
    })?;
    if value.is_empty() {
        return Err(refused(
            ERROR_KIND_INVALID,
            format!("secret double (env): variable {var} is empty"),
        ));
    }
    Ok(value.into_bytes())
}

fn resolve_file(settings: &[u8]) -> Result<Vec<u8>, SecretRefused> {
    let path = setting(settings, SECRET_MODULE_FILE, SECRET_FILE_SETTING_PATH)?;
    let bytes = std::fs::read(&path).map_err(|e| {
        let kind = if e.kind() == std::io::ErrorKind::NotFound {
            ERROR_KIND_NOT_FOUND
        } else {
            ERROR_KIND_UNAVAILABLE
        };
        refused(
            kind,
            format!("secret double (file): {path} unreadable: {e}"),
        )
    })?;
    if bytes.is_empty() {
        return Err(refused(
            ERROR_KIND_INVALID,
            format!("secret double (file): {path} is empty"),
        ));
    }
    Ok(bytes)
}

impl SecretCalls for Double {
    fn resolve(&self, settings: &[u8]) -> Result<Redacted<Vec<u8>>, SecretRefused> {
        match self {
            Double::Env => resolve_env(settings),
            Double::File => resolve_file(settings),
        }
        .map(Redacted::new)
    }
}

impl SecretAxis for SecretsStandIn {
    fn answers(&self, module: &str) -> bool {
        double(module).is_some()
    }

    fn linked(&self, module: &str) -> bool {
        double(module).is_some()
    }

    fn shared(&self, module: &str) -> Result<Arc<dyn SecretCalls>, String> {
        double(module)
            .map(|d| Arc::new(d) as Arc<dyn SecretCalls>)
            .ok_or_else(|| format!("no linked secret module answers to '{module}'"))
    }

    fn open(
        &self,
        module: &str,
        _: &serde_json::Value,
        _: &dyn Fn(&SecretRef) -> Result<Vec<u8>, String>,
    ) -> Result<Arc<dyn SecretCalls>, String> {
        self.shared(module)
    }
}
