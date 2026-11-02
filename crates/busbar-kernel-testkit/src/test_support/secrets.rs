// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

const ENV_NEEDS_KEY: &str = "secret module 'env' requires settings.key naming the environment \
     variable (e.g. `{ env: MY_VAR }` or `{ module: env, settings: { key: MY_VAR } }`)";

const FILE_NEEDS_PATH: &str = "secret module 'file' requires settings.path naming the file \
     (e.g. `{ file: /run/secrets/x }` or `{ module: file, settings: { path: /run/secrets/x } }`)";

fn setting(settings: &[u8], field: &str, missing: &str) -> Result<String, SecretRefused> {
    let doc: serde_json::Map<String, serde_json::Value> = if settings.is_empty() {
        serde_json::Map::new()
    } else {
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
        return Err(refused(
            ERROR_KIND_NOT_FOUND,
            format!(
                "secret {SECRET_MODULE_ENV}:{var} cannot resolve: environment variable '{var}' is \
                 unset"
            ),
        ));
    };
    let value = raw.into_string().map_err(|_| {
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
