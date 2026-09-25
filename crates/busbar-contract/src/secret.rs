// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The SECRET-MODULE contract (`kind: secret` plugins). A secret module turns a config secret
//! reference's opaque `settings` into the secret BYTES: the built-in `env` module reads an
//! environment variable (settings.key), the built-in `file` module reads a file (settings.path),
//! and a third-party module (vault, a cloud secret manager, a database) implements the same trait
//! behind the plugin trust pipeline. The engine sees only `dyn SecretModule` - never the
//! implementation - and treats every failure as FAIL-CLOSED (an unresolvable secret refuses boot,
//! never resolves empty).
//!
//! Moved here, module-path-only, from `busbar-api` (DECISIONS #83/#84; the per-kind trait is the
//! contract's, #35(a)). The error is [`SecretModuleError`] here because [`crate::kinds::SecretError`]
//! is a different type (#35 de-collision); `busbar-api` re-exports it as `SecretError`, and its
//! `Debug` keeps that label so every rendering is byte-identical. The BUILT-IN resolution
//! (`resolve_builtin`, the `env`/`file` readers) did not come: it reads the environment and the
//! filesystem, which is machinery, not a shape (#83(b)). Nor did the `SecretResolve` seam: it takes
//! the config secret reference, whose own crate merges into this one only with the fold that
//! deletes it (a shim re-exporting from here would be a new plugin-tooling -> contract edge).

/// The result type every [`SecretModule`] call returns.
pub type SecretResult<T> = Result<T, SecretModuleError>;

/// The taxonomy a [`SecretModuleError`] carries: distinguishes a
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
pub struct SecretModuleError {
    pub kind: SecretErrorKind,
    pub message: String,
}

impl SecretModuleError {
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

// MANUAL `Debug`, byte-identical to the derive this type carried as `busbar_api::SecretError`: the
// rename is a module-path de-collision (#35), and a `{:?}` in a log line must not change with it.
impl std::fmt::Debug for SecretModuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretError")
            .field("kind", &self.kind)
            .field("message", &self.message)
            .finish()
    }
}

impl std::fmt::Display for SecretModuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "secret error ({:?}): {}", self.kind, self.message)
    }
}
impl std::error::Error for SecretModuleError {}

/// Every error constructed before this taxonomy existed becomes `Internal` — behaviorally identical
/// to the old bare-string error (same message, same fail-closed treatment), just now typed.
impl From<String> for SecretModuleError {
    fn from(s: String) -> Self {
        SecretModuleError::internal(s)
    }
}
impl From<&str> for SecretModuleError {
    fn from(s: &str) -> Self {
        SecretModuleError::internal(s)
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

    /// Resolve with the caller's ADVISORY deadline, in milliseconds from now (`None` = the caller
    /// set no bound). The wire request has always carried this field and the dispatcher has always
    /// dropped it on the floor, so a module that CAN bound its own upstream call — an HTTP vault
    /// client, a socket to an agent — had no way to learn what bound to apply, and the engine's
    /// deadline was enforced only by whatever timeout the engine itself wrapped the call in.
    ///
    /// Defaulted to [`resolve`](Self::resolve) so it is purely additive: a module that cannot bound
    /// itself, or does not care, implements nothing and behaves exactly as before. The deadline is
    /// ADVISORY — honoring it is a courtesy that lets the module fail fast with its own error rather
    /// than be abandoned mid-call; it is never the only thing standing between the engine and a hung
    /// module.
    fn resolve_with_deadline(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
        deadline_ms: Option<u64>,
    ) -> SecretResult<Vec<u8>> {
        let _ = deadline_ms;
        self.resolve(settings)
    }
}
