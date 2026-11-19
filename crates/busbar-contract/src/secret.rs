// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The SECRET-MODULE contract (`kind: secret` plugins). A secret module turns a config secret

pub mod codes;
use crate::secret_ref::SecretRef;

/// RESOLVED SECRET BYTES, as the host holds them: the
pub type SecretBytes = crate::redacted::Secret<Vec<u8>>;

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
    /// The secret shorthand of the configuration generation this resolver serves: what a reference
    /// written in that generation is read under. `None` for a resolver bound to no generation,
    /// which reads canonical `{ module, settings }` references only.
    fn sources(&self) -> Option<&crate::secret_ref::Sugars> {
        None
    }

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
            error_kind: crate::secret::codes::ERROR_KIND_INTERNAL,
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

    /// Whether this instance was opened with secret material lent from its own references, so a
    /// [`Self::relend`] can find it rotated (the host polls only such instances).
    fn relends(&self) -> bool {
        false
    }

    /// RE-LEND: re-resolve the references this instance was opened with through `resolve` and,
    /// when the material changed, hand it to the plugin's `refresh` (or, for a plugin with no
    /// `refresh`, open a new instance from the same artifact for the caller to swap in). A refusal
    /// leaves this instance exactly as it was.
    fn relend(
        &self,
        resolve: &dyn Fn(&SecretRef) -> Result<SecretBytes, String>,
    ) -> Result<SecretRelent, RelendRefused> {
        let _ = resolve;
        Ok(SecretRelent::Unchanged)
    }

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
    fn check(
        &self,
        _module: &str,
        _settings: &crate::plugin_settings::Settings,
    ) -> Result<(), Vec<String>> {
        Ok(())
    }

    /// The process's ONE instance of the linked plugin `module` names, opened on first use with no
    fn shared(&self, module: &str) -> Result<std::sync::Arc<dyn SecretCalls>, String>;

    /// OPEN a new instance of `module` over its module-level `settings` (as written: a secret
    fn open(
        &self,
        module: &str,
        settings: Option<&crate::plugin_settings::Settings>,
        resolve: &dyn Fn(&SecretRef) -> Result<SecretBytes, String>,
    ) -> Result<std::sync::Arc<dyn SecretCalls>, String>;
}

/// What a secret instance's [`SecretCalls::relend`] did.
pub enum SecretRelent {
    /// The lent material is unchanged: nothing was called.
    Unchanged,
    /// The plugin's `refresh` adopted the new material in place.
    Refreshed,
    /// The plugin has no `refresh`: a new instance from the same artifact opened over the new
    /// material, for the caller to swap in (the old one closes when its last caller lets go).
    Reopened(std::sync::Arc<dyn SecretCalls>),
}

impl std::fmt::Debug for SecretRelent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unchanged => "Unchanged",
            Self::Refreshed => "Refreshed",
            Self::Reopened(_) => "Reopened",
        })
    }
}

/// What an auth instance's re-lend did (`auth_calls::AuthCalls::relend`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRelent {
    /// The lent material is unchanged: nothing was called.
    Unchanged,
    /// The plugin's `refresh` adopted the new material in place.
    Refreshed,
    /// The plugin has no `refresh`: the caller opens a new instance and swaps it in.
    NotRefreshed,
}

/// Why a re-lend did not apply; the running instance is kept as it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelendRefused {
    /// Which step refused.
    pub cause: RelendCause,
    /// The operator's words (never secret material).
    pub text: String,
}

/// The step of a re-lend that refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelendCause {
    /// A reference could not be re-resolved.
    Unresolvable,
    /// The plugin's `refresh` refused the new material.
    Refused,
    /// The new instance (a plugin with no `refresh`) did not open.
    ReopenFailed,
    /// DES-454: two reads of an unleased source disagreed, or a binding outside the rotation no longer matches
    /// what the instance committed.
    Unstable,
    /// DES-454: a rotation call held or waited for its permit past the poll deadline.
    Deadline,
    /// DES-454: the export successor differs in shape from the instance it would replace.
    ShapeChanged,
    /// DES-454 (PM D1): a non-export kind takes a rotated value only at the next reload or restart.
    ReloadRequired,
    /// DES-454: the process store takes a rotated value only at restart.
    RestartRequired,
}

impl RelendCause {
    /// The cause as the diagnostic's `cause` field spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unresolvable => "unresolvable",
            Self::Refused => "refused",
            Self::ReopenFailed => "reopen-failed",
            Self::Unstable => "unstable",
            Self::Deadline => "deadline",
            Self::ShapeChanged => "shape-changed",
            Self::ReloadRequired => "reload-required",
            Self::RestartRequired => "restart-required",
        }
    }
}
