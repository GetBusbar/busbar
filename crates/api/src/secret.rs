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
