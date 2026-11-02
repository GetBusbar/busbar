// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The SECRET-MODULE contract (`kind: secret` plugins). A secret module turns a config secret

use crate::secret_ref::SecretRef;

/// RESOLVED SECRET BYTES, as the host holds them: the
pub type SecretBytes = crate::redacted::Secret<Vec<u8>>;

/// The result type every secret module call returns.
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

/// The NEUTRAL secret-resolver SEAM an extracted plane names instead of the engine's concrete
pub trait SecretResolve: Send + Sync {
    /// Resolve a reference to raw bytes (fail-closed). Some consumers — a raw-file loader, for
    fn resolve(&self, secret: &SecretRef) -> Result<crate::redacted::Secret<Vec<u8>>, String>;

    /// Resolve a reference to UTF-8 TEXT (trailing newline trimmed; fail-closed on non-UTF-8 or
    fn resolve_string(&self, secret: &SecretRef)
        -> Result<crate::redacted::Secret<String>, String>;

    /// [`Self::resolve`] at CONFIG TIME, with its proof: the one way a reference to a source that
    fn resolve_at_config(
        &self,
        secret: &SecretRef,
        _scope: &crate::config_time::ConfigScope,
    ) -> Result<crate::redacted::Secret<Vec<u8>>, String> {
        self.resolve(secret)
    }

    /// [`Self::resolve_string`] at CONFIG TIME, with its proof (see [`Self::resolve_at_config`]).
    fn resolve_string_at_config(
        &self,
        secret: &SecretRef,
        _scope: &crate::config_time::ConfigScope,
    ) -> Result<crate::redacted::Secret<String>, String> {
        self.resolve_string(secret)
    }

    /// [`Self::resolve`] (or, with `scope`, [`Self::resolve_at_config`]) whose refusal KEEPS the
    fn resolve_refusing(
        &self,
        secret: &SecretRef,
        scope: Option<&crate::config_time::ConfigScope>,
    ) -> Result<crate::redacted::Secret<Vec<u8>>, SecretRefused> {
        match scope {
            Some(scope) => self.resolve_at_config(secret, scope),
            None => self.resolve(secret),
        }
        .map_err(|text| SecretRefused {
            error_kind: crate::abi::secret::ERROR_KIND_INTERNAL,
            text,
        })
    }
}

/// How a secret plugin refused a `resolve`: the `abi::secret::ERROR_KIND_*` code its answer carried
/// and the operator-facing text (never secret material; the host passes it through verbatim).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRefused {
    /// One of `abi::secret::ERROR_KIND_*`; `ERROR_KIND_INTERNAL` when the plugin faulted or timed
    /// out rather than answering.
    pub error_kind: u32,
    /// The refusal text.
    pub text: String,
}

/// ONE OPENED SECRET PLUGIN INSTANCE'S CALLS, as the kernel's secret resolver makes them (every
pub trait SecretCalls: Send + Sync {
    /// `resolve` one reference's `settings` object (JSON bytes) to the secret's material, which the
    fn resolve(&self, settings: &[u8]) -> Result<crate::redacted::Secret<Vec<u8>>, SecretRefused>;

    /// `resolve` at CONFIG TIME, with its proof ([`ConfigScope`](crate::config_time::ConfigScope)):
    fn resolve_at_config(
        &self,
        settings: &[u8],
        _scope: &crate::config_time::ConfigScope,
    ) -> Result<crate::redacted::Secret<Vec<u8>>, SecretRefused> {
        self.resolve(settings)
    }
}

/// The secret axis the composition root hands to the kernel, through
pub trait SecretAxis: Send + Sync {
    /// The SUGARS the admitted secret plugins' Statements declare (audit contract-admin #10, Law 1:
    fn sugars(&self) -> crate::secret_ref::Sugars;

    /// Whether a secret plugin answers `module`, linked or dropped in.
    fn answers(&self, module: &str) -> bool;

    /// Whether `module` names a secret plugin this build LINKS (a reference to it needs no
    fn linked(&self, module: &str) -> bool;

    /// JUDGE one reference to `module` at config time, before anything resolves: its plugin's
    fn check(&self, _module: &str, _settings: &serde_json::Value) -> Result<(), Vec<String>> {
        Ok(())
    }

    /// The process's ONE instance of the linked plugin `module` names, opened on first use with no
    fn shared(&self, module: &str) -> Result<std::sync::Arc<dyn SecretCalls>, String>;

    /// OPEN a new instance of `module` over its module-level `settings` (as written: a secret
    fn open(
        &self,
        module: &str,
        settings: &serde_json::Value,
        resolve: &dyn Fn(&SecretRef) -> Result<SecretBytes, String>,
    ) -> Result<std::sync::Arc<dyn SecretCalls>, String>;
}
