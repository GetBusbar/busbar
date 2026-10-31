// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECRET DOUBLE: the kernel's own secret port — the contract's [`SecretAxis`] /
//! [`SecretCalls`], the seam the composition root installs and the kernel names nothing behind —
//! answered in process, so the kernel's tests resolve `{ env: VAR }` / `{ file: PATH }` references
//! with no secret plugin linked (ARCHITECT R-FIX3, 2026-09-26: a behaviour double the kernel's own
//! tests need lives in-crate, linked only). It is not a plugin and not a door, and it names neither
//! plugin crate.
//!
//! FAITHFUL TEXT (coordinator ruling on #565, 2026-10-07): every refusal the double produces is the
//! shipped source's, byte for byte, and its error kind is the source's; each string cites the ITEM
//! of the source it reproduces (`env::resolve` is the env source's `resolve`, `file::io_refusal`
//! the file source's `io_refusal`, at whatever rev the workspace root pins: an item name does not
//! go stale when a pin moves its lines; the module names are the contract's constants, never
//! spelled here). A pin bump that changes a refusal changes it here too; the root's suite
//! (`crates/busbar/src/root/tests/linked_secret_sources.rs`, `root/tests/linked.rs`) pins the real
//! sources' words through the linked axis, so the two cannot drift silently apart.
//!
//! It produces a subset of the sources' refusals, the ones the kernel's tests need: a missing /
//! blank `key` / `path`, an unset or non-UTF-8 variable, an unreadable file, an empty value. The sources' own guards beyond those (the blank
//! value / blank file rule, the regular-file check, the size cap) are theirs alone and are proven at
//! the root. A value it returns is the source's bytes, untouched.

use std::sync::Arc;

use busbar_contract::abi::mechanism::door::{
    REWRITE_SUGAR, REWRITE_SUGAR_NAMES, REWRITE_SUGAR_ROLE, SUGAR_ROLE_FILL, SUGAR_ROLE_PATH,
};
use busbar_contract::abi::secret::{
    ERROR_KIND_DENIED, ERROR_KIND_INVALID, ERROR_KIND_NOT_FOUND, ERROR_KIND_UNAVAILABLE,
};
use busbar_contract::redacted::Secret;
use busbar_contract::secret::{SecretAxis, SecretCalls, SecretRefused};
use busbar_contract::secret_ref::{
    SecretRef, Sugars, SECRET_ENV_SETTING_KEY, SECRET_FILE_SETTING_PATH, SECRET_MODULE_ENV,
    SECRET_MODULE_FILE,
};

/// The stand-in secret axis a test build installs in place of the root's (`test_support::root::STAND_IN`).
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

/// The env source's refusal of a missing / blank `key` (`env::resolve`).
const ENV_NEEDS_KEY: &str = "secret module 'env' requires settings.key naming the environment \
     variable (e.g. `{ env: MY_VAR }` or `{ module: env, settings: { key: MY_VAR } }`)";

/// The file source's refusal of a missing / blank `path` (`file::resolve`).
const FILE_NEEDS_PATH: &str = "secret module 'file' requires settings.path naming the file \
     (e.g. `{ file: /run/secrets/x }` or `{ module: file, settings: { path: /run/secrets/x } }`)";

/// The non-blank string setting `field` of a settings document; `missing` is the source's refusal
/// when it is absent or blank.
fn setting(settings: &[u8], field: &str, missing: &str) -> Result<String, SecretRefused> {
    // The kernel's resolver hands every call the reference's settings as a JSON object
    // (`config::secret::SecretResolver::resolve`), so a document that is not one is a broken
    // caller, not an operator's refusal: the double does not produce the sources' "secret settings
    // are not a JSON object" refusal (`env::settings_of`, `file::settings_of`),
    // and a test that reaches this fails loudly.
    let doc: serde_json::Map<String, serde_json::Value> = if settings.is_empty() {
        serde_json::Map::new()
    } else {
        // Panics by design (coordinator ruling on #565): the kernel always passes an object, and the plugins' faithful "secret settings are not a JSON object" text trips secret-hygiene check3.
        serde_json::from_slice(settings)
            .expect("the kernel hands a secret module its settings as a JSON object")
    };
    match doc.get(field).and_then(|v| v.as_str()) {
        Some(v) if !v.trim().is_empty() => Ok(v.to_string()),
        _ => Err(refused(ERROR_KIND_INVALID, missing.to_string())),
    }
}

fn resolve_env(settings: &[u8]) -> Result<Vec<u8>, SecretRefused> {
    let var = setting(settings, SECRET_ENV_SETTING_KEY, ENV_NEEDS_KEY)?;
    let Some(raw) = std::env::var_os(&var) else {
        // `env::resolve`, the unset variable (NotFound).
        return Err(refused(
            ERROR_KIND_NOT_FOUND,
            format!(
                "secret {SECRET_MODULE_ENV}:{var} cannot resolve: environment variable '{var}' is \
                 unset"
            ),
        ));
    };
    let value = raw.into_string().map_err(|_| {
        // `env::resolve`, the non-UTF-8 value (Invalid).
        refused(
            ERROR_KIND_INVALID,
            format!(
                "secret {SECRET_MODULE_ENV}:{var} cannot resolve: environment variable '{var}' IS \
                 SET but its \
                 value is not valid UTF-8, so it cannot be read as a secret — this is an \
                 ENCODING problem, not a missing variable; re-export it as UTF-8 (setting it \
                 again will not help)"
            ),
        )
    })?;
    if value.is_empty() {
        // `env::resolve`, the empty value (Invalid).
        return Err(refused(
            ERROR_KIND_INVALID,
            format!(
                "secret {SECRET_MODULE_ENV}:{var} resolved to an EMPTY value; a secret must be \
                 non-empty (fail-closed)"
            ),
        ));
    }
    Ok(value.into_bytes())
}

fn resolve_file(settings: &[u8]) -> Result<Vec<u8>, SecretRefused> {
    let path = setting(settings, SECRET_FILE_SETTING_PATH, FILE_NEEDS_PATH)?;
    let bytes = std::fs::read(&path).map_err(|e| {
        // The kind is the source's io mapping and the text its io refusal (`file::io_refusal`).
        let kind = match e.kind() {
            std::io::ErrorKind::NotFound => ERROR_KIND_NOT_FOUND,
            std::io::ErrorKind::PermissionDenied => ERROR_KIND_DENIED,
            std::io::ErrorKind::Other => ERROR_KIND_INVALID,
            _ => ERROR_KIND_UNAVAILABLE,
        };
        refused(
            kind,
            format!("secret {SECRET_MODULE_FILE}:{path} cannot resolve: {e}"),
        )
    })?;
    if bytes.is_empty() {
        // `file::resolve`, the empty file (Invalid).
        return Err(refused(
            ERROR_KIND_INVALID,
            format!(
                "secret {SECRET_MODULE_FILE}:{path} resolved to an EMPTY file; a secret must be \
                 non-empty (fail-closed)"
            ),
        ));
    }
    Ok(bytes)
}

impl SecretCalls for Double {
    fn resolve(&self, settings: &[u8]) -> Result<Secret<Vec<u8>>, SecretRefused> {
        match self {
            Double::Env => resolve_env(settings),
            Double::File => resolve_file(settings),
        }
        .map(Secret::new)
    }
}

/// The shorthand each double's source declares in its Statement (env src/door.rs and file
/// src/door.rs at the revs the workspace root pins): its word, the settings key its value lands
/// under, what a refusal says the value names (1.5.5's words, v1.5.5
/// crates/busbar/src/config_validate/mod.rs:1678 and :1682) and its core role. Declared through
/// the contract's one reader, as the loader declares the real Statements' rewrites.
fn declared() -> Sugars {
    let sources = [
        (
            SECRET_MODULE_ENV,
            SECRET_ENV_SETTING_KEY,
            "the environment variable name",
            SUGAR_ROLE_FILL,
        ),
        (
            SECRET_MODULE_FILE,
            SECRET_FILE_SETTING_PATH,
            "the file to read",
            SUGAR_ROLE_PATH,
        ),
    ];
    let mut sugars = Sugars::default();
    for (word, key, names, role) in sources {
        let fact = |class: u32, to: &str| (class, word.to_string(), to.to_string());
        sugars
            .declare(
                word,
                &[
                    fact(REWRITE_SUGAR, key),
                    fact(REWRITE_SUGAR_NAMES, names),
                    fact(REWRITE_SUGAR_ROLE, role),
                ],
            )
            .expect("the doubles' shorthand declares");
    }
    sugars
}

impl SecretAxis for SecretsStandIn {
    fn sugars(&self) -> Sugars {
        declared()
    }

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
        _: &dyn Fn(&SecretRef) -> Result<busbar_contract::redacted::Secret<Vec<u8>>, String>,
    ) -> Result<Arc<dyn SecretCalls>, String> {
        self.shared(module)
    }
}
