// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The SECRET-MODULE contract (`kind: secret` plugins). A secret module turns a config secret
//! reference's opaque `settings` into the secret BYTES: the built-in `env` module reads an
//! environment variable (settings.key), the built-in `file` module reads a file (settings.path),
//! and a third-party module (vault, a cloud secret manager, a database) implements the same trait
//! behind the plugin trust pipeline. The engine sees only `dyn SecretModule` - never the
//! implementation - and treats every failure as FAIL-CLOSED (an unresolvable secret refuses boot,
//! never resolves empty).

/// The result type every [`SecretModule`] call returns.
pub type SecretResult<T> = Result<T, SecretError>;

/// The taxonomy a [`SecretError`] carries: distinguishes a
/// configuration problem an operator must fix (`NotFound`, `Invalid`, `Denied`) from an outage they
/// must wait out (`Unavailable`) — conflating the two, as a bare string does, produces exactly the
/// wrong operator response in both directions. `Internal` is the catch-all for anything that
/// doesn't fit the other four (including every pre-existing untyped-string error, via `From<String>`
/// / `From<&str>` below, so no existing caller breaks).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretErrorKind {
    /// The referenced secret does not exist at the source (wrong key/path/name) — a config error.
    NotFound,
    /// The source could not be reached (network, auth-to-the-backend, timeout) — an outage.
    Unavailable,
    /// The caller is not permitted to read this secret — a config/policy error.
    Denied,
    /// The request itself is malformed (bad settings shape) — a config error.
    Invalid,
    /// Anything else, including every error that predates this taxonomy.
    Internal,
}

/// A secret-resolution failure: a [`SecretErrorKind`] plus a human-readable message. The message
/// must NEVER carry secret material - name the source (variable name, path, module) and the
/// failure, not the value.
#[derive(Debug)]
pub struct SecretError {
    pub kind: SecretErrorKind,
    pub message: String,
}

impl SecretError {
    pub fn new(kind: SecretErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(SecretErrorKind::NotFound, message)
    }
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(SecretErrorKind::Unavailable, message)
    }
    pub fn denied(message: impl Into<String>) -> Self {
        Self::new(SecretErrorKind::Denied, message)
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(SecretErrorKind::Invalid, message)
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(SecretErrorKind::Internal, message)
    }
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "secret error ({:?}): {}", self.kind, self.message)
    }
}
impl std::error::Error for SecretError {}

/// Every error constructed before this taxonomy existed becomes `Internal` — behaviorally identical
/// to the old bare-string error (same message, same fail-closed treatment), just now typed.
impl From<String> for SecretError {
    fn from(s: String) -> Self {
        SecretError::internal(s)
    }
}
impl From<&str> for SecretError {
    fn from(s: &str) -> Self {
        SecretError::internal(s)
    }
}

/// One secret module - a resolver from a secret reference's `settings` map to the secret bytes.
/// Stateless per call: one module instance serves EVERY reference naming it, each carrying its own
/// `settings` (the `{ module: vault, settings: { path: kv/x } }` shape), so `resolve` takes the
/// settings per call rather than at construction. Off every hot path (secrets resolve at boot /
/// first use), so a plain synchronous call is the whole contract.
pub trait SecretModule: Send + Sync + 'static {
    /// Resolve one reference's settings to the secret bytes. FAIL-CLOSED: an unknown setting, a
    /// missing source, or an EMPTY value is an error, never `Ok(vec![])` - the engine additionally
    /// rejects an empty success defensively.
    fn resolve(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
    ) -> SecretResult<Vec<u8>>;
}

use busbar_secret_ref::{SecretRef, SECRET_MODULE_ENV, SECRET_MODULE_FILE};

/// BUILT-IN resolution of a secret reference to its raw bytes: `env` reads the
/// environment variable; `file` reads the file. Any other module name is FAIL-CLOSED here - the
/// full secret-plugin resolver (third-party `kind: secret` modules through the plugin trust
/// pipeline) is layered on top of this by the engine's `SecretResolver`, which falls back to these
/// built-ins by these exact names.
pub fn resolve_builtin(secret: &SecretRef) -> Result<Vec<u8>, String> {
    if let Some(var) = self_env_var_checked(secret)? {
        return match std::env::var(&var) {
            Ok(v) if !v.is_empty() => Ok(v.into_bytes()),
            Ok(_) => Err(format!(
                "secret env:{var} resolved to an EMPTY value; a secret must be non-empty \
                 (fail-closed)"
            )),
            Err(_) => Err(format!(
                "secret env:{var} cannot resolve: environment variable '{var}' is unset"
            )),
        };
    }
    if let Some(path) = self_file_path_checked(secret)? {
        return match std::fs::read(&path) {
            Ok(bytes) if !bytes.is_empty() => Ok(bytes),
            Ok(_) => Err(format!(
                "secret file:{path} resolved to an EMPTY file; a secret must be non-empty \
                 (fail-closed)"
            )),
            Err(e) => Err(format!("secret file:{path} cannot resolve: {e}")),
        };
    }
    Err(format!(
        "secret module '{}' is not a built-in (`env` / `file`) and no secret plugin provides it; \
         a secret that cannot resolve is a hard error (fail-closed)",
        secret.module
    ))
}

/// The `env` module's variable name, validating the settings shape (a malformed built-in ref must
/// fail loudly, not fall through to "unknown module").
fn self_env_var_checked(secret: &SecretRef) -> Result<Option<String>, String> {
    if secret.module != SECRET_MODULE_ENV {
        return Ok(None);
    }
    match secret.env_var() {
        Some(v) if !v.trim().is_empty() => Ok(Some(v.to_string())),
        _ => Err(
            "secret module 'env' requires settings.key naming the environment variable \
             (e.g. `{ env: MY_VAR }` or `{ module: env, settings: { key: MY_VAR } }`)"
                .to_string(),
        ),
    }
}

/// The `file` module's path, validating the settings shape.
fn self_file_path_checked(secret: &SecretRef) -> Result<Option<String>, String> {
    if secret.module != SECRET_MODULE_FILE {
        return Ok(None);
    }
    match secret.file_path() {
        Some(p) if !p.trim().is_empty() => Ok(Some(p.to_string())),
        _ => Err(
            "secret module 'file' requires settings.path naming the file \
             (e.g. `{ file: /run/secrets/x }` or `{ module: file, settings: { path: /run/secrets/x } }`)"
                .to_string(),
        ),
    }
}

/// The NEUTRAL secret-resolver SEAM an extracted plane names instead of the engine's concrete
/// `SecretResolver`. A plane (a2a delegation-credential minting, TLS PEM loading) only needs to turn
/// a [`SecretRef`] into bytes or a UTF-8 string; naming this trait — not the core struct — keeps the
/// plane free of an engine dependency. The engine's `SecretResolver` implements it (delegating to
/// its own resolution), and `EngineHost` hands the plane an `Arc<dyn SecretResolve>` snapshot.
///
/// FAIL-CLOSED, exactly as the underlying resolver: an unknown module, an unset source, or an empty
/// value is an `Err(String)`, never an empty secret. The error is a neutral `String` — a plane never
/// sees an engine-only error type across this seam.
pub trait SecretResolve: Send + Sync {
    /// Resolve a reference to raw bytes (fail-closed). The TLS plane's PEM loader needs the raw
    /// bytes, not a trimmed string.
    fn resolve(&self, secret: &SecretRef) -> Result<Vec<u8>, String>;

    /// Resolve a reference to a UTF-8 STRING (trailing newline trimmed; fail-closed on non-UTF-8 or
    /// empty). The a2a credential-minting path needs the string form.
    fn resolve_string(&self, secret: &SecretRef) -> Result<String, String>;
}

/// Resolve a secret reference to a UTF-8 STRING (trailing newline trimmed - the universal
/// file-delivered-secret convention). Fail-closed on non-UTF-8.
pub fn resolve_builtin_string(secret: &SecretRef) -> Result<String, String> {
    let bytes = resolve_builtin(secret)?;
    let s = String::from_utf8(bytes).map_err(|_| {
        format!(
            "secret {} resolved to non-UTF-8 bytes where a text secret is required",
            secret.describe()
        )
    })?;
    let trimmed = s.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        return Err(format!(
            "secret {} resolved to an empty value after trimming trailing newlines (fail-closed)",
            secret.describe()
        ));
    }
    Ok(trimmed.to_string())
}
