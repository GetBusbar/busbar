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
//! shipped source's, byte for byte, and its error kind is the source's; each string cites the line
//! of the pinned source it reproduces (`busbar-secret-env` at rev 495318c, `secret-env/src/lib.rs`;
//! `busbar-secret-file` at rev 479c833, `secret-file/src/lib.rs` — the revs the workspace root
//! pins). A rev bump that changes a refusal changes it here too; the root's suite
//! (`crates/busbar/src/root/tests/linked_secret_sources.rs`, `root/tests/linked.rs`) pins the real
//! sources' words through the linked axis, so the two cannot drift silently apart.
//!
//! It produces a subset of the sources' refusals, the ones the kernel's tests need: a missing /
//! blank `key` / `path`, an unset or non-UTF-8 variable, an unreadable file, an empty value. The sources' own guards beyond those (the blank
//! value / blank file rule, the regular-file check, the size cap) are theirs alone and are proven at
//! the root. A value it returns is the source's bytes, untouched.

use std::sync::Arc;

use busbar_contract::abi::secret::{
    ERROR_KIND_DENIED, ERROR_KIND_INVALID, ERROR_KIND_NOT_FOUND, ERROR_KIND_UNAVAILABLE,
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

/// The env source's refusal of a missing / blank `key` (secret-env/src/lib.rs:42-45 @ 495318c).
const ENV_NEEDS_KEY: &str = "secret module 'env' requires settings.key naming the environment \
     variable (e.g. `{ env: MY_VAR }` or `{ module: env, settings: { key: MY_VAR } }`)";

/// The file source's refusal of a missing / blank `path` (secret-file/src/lib.rs:83-86 @ 479c833).
const FILE_NEEDS_PATH: &str = "secret module 'file' requires settings.path naming the file \
     (e.g. `{ file: /run/secrets/x }` or `{ module: file, settings: { path: /run/secrets/x } }`)";

/// The non-blank string setting `field` of a settings document; `missing` is the source's refusal
/// when it is absent or blank.
fn setting(settings: &[u8], field: &str, missing: &str) -> Result<String, SecretRefused> {
    // The kernel's resolver hands every call the reference's settings as a JSON object
    // (`config::secret::SecretResolver::resolve`), so a document that is not one is a broken
    // caller, not an operator's refusal: the double does not produce the sources' "secret settings
    // are not a JSON object" refusal (secret-env/src/lib.rs:95 @ 495318c, secret-file/src/lib.rs:141
    // @ 479c833), and a test that reaches this fails loudly.
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
        // secret-env/src/lib.rs:55-57 @ 495318c (NotFound).
        return Err(refused(
            ERROR_KIND_NOT_FOUND,
            format!("secret env:{var} cannot resolve: environment variable '{var}' is unset"),
        ));
    };
    let value = raw.into_string().map_err(|_| {
        // secret-env/src/lib.rs:62-67 @ 495318c (Invalid).
        refused(
            ERROR_KIND_INVALID,
            format!(
                "secret env:{var} cannot resolve: environment variable '{var}' IS SET but its \
                 value is not valid UTF-8, so it cannot be read as a secret — this is an \
                 ENCODING problem, not a missing variable; re-export it as UTF-8 (setting it \
                 again will not help)"
            ),
        )
    })?;
    if value.is_empty() {
        // secret-env/src/lib.rs:68-71 @ 495318c (Invalid).
        return Err(refused(
            ERROR_KIND_INVALID,
            format!(
                "secret env:{var} resolved to an EMPTY value; a secret must be non-empty \
                 (fail-closed)"
            ),
        ));
    }
    Ok(value.into_bytes())
}

fn resolve_file(settings: &[u8]) -> Result<Vec<u8>, SecretRefused> {
    let path = setting(settings, SECRET_FILE_SETTING_PATH, FILE_NEEDS_PATH)?;
    let bytes = std::fs::read(&path).map_err(|e| {
        // The kind is the source's io mapping (secret-file/src/lib.rs:62-67 @ 479c833), the text
        // its io refusal (secret-file/src/lib.rs:68 @ 479c833).
        let kind = match e.kind() {
            std::io::ErrorKind::NotFound => ERROR_KIND_NOT_FOUND,
            std::io::ErrorKind::PermissionDenied => ERROR_KIND_DENIED,
            std::io::ErrorKind::Other => ERROR_KIND_INVALID,
            _ => ERROR_KIND_UNAVAILABLE,
        };
        refused(kind, format!("secret file:{path} cannot resolve: {e}"))
    })?;
    if bytes.is_empty() {
        // secret-file/src/lib.rs:112-115 @ 479c833 (Invalid).
        return Err(refused(
            ERROR_KIND_INVALID,
            format!(
                "secret file:{path} resolved to an EMPTY file; a secret must be non-empty \
                 (fail-closed)"
            ),
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
