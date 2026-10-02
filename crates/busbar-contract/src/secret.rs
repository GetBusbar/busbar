// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The SECRET-MODULE contract (`kind: secret` plugins). A secret module turns a config secret
//! reference's opaque `settings` into the secret BYTES: the `env` plugin reads an environment
//! variable (settings.key), the `file` plugin reads a file (settings.path), and a third-party module
//! (vault, a cloud secret manager, a database) implements the same contract behind the plugin trust
//! pipeline. The engine sees only the contract - never the implementation - and treats every
//! failure as FAIL-CLOSED (an unresolvable secret refuses boot, never resolves empty).
//!
//! Moved here, module-path-only, from `busbar-api` (DECISIONS #83/#84; the per-kind trait is the
//! contract's, #35(a)). The error is [`SecretModuleError`] here because [`crate::kinds::SecretError`]
//! is a different type (#35 de-collision); its `Debug` keeps the historical `SecretError` label so
//! every rendering is byte-identical. The `env`/`file` sources are ordinary secret-kind plugins in
//! their own repos (`busbar-secret-env`, `busbar-secret-file`; THE DESIGN, "Plugins"), called through the
//! secret kind table; the kernel reaches every loaded secret plugin through [`SecretAxis`] and
//! [`SecretCalls`]. The [`SecretResolve`] seam followed the config secret reference it takes into
//! this crate once that reference merged here, when `busbar-api` retired.

use crate::secret_ref::SecretRef;

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

// MANUAL `Debug`, byte-identical to the derive this type carried as `crate::secret::SecretModuleError`: the
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

/// The NEUTRAL secret-resolver SEAM an extracted plane names instead of the engine's concrete
/// `SecretResolver`. A plane only needs to turn a [`SecretRef`] into bytes or a UTF-8 string;
/// naming this trait — not the core struct — keeps the plane free of an engine dependency. The
/// engine's `SecretResolver` implements it (delegating to its own resolution), and `EngineHost`
/// hands the plane an `Arc<dyn SecretResolve>` snapshot.
///
/// FAIL-CLOSED, exactly as the underlying resolver: an unknown module, an unset source, or an empty
/// value is an `Err(String)`, never an empty secret. The error is a neutral `String` — a plane never
/// sees an engine-only error type across this seam.
pub trait SecretResolve: Send + Sync {
    /// Resolve a reference to raw bytes (fail-closed). Some consumers — a raw-file loader, for
    /// instance — need the untrimmed bytes rather than a string.
    fn resolve(&self, secret: &SecretRef) -> Result<Vec<u8>, String>;

    /// Resolve a reference to a UTF-8 STRING (trailing newline trimmed; fail-closed on non-UTF-8 or
    /// empty). Some consumers — a credential-minting path, for instance — need the string form.
    fn resolve_string(&self, secret: &SecretRef) -> Result<String, String>;
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
/// secret resolution crosses the secret kind table through the one dispatcher). The plugin loader
/// implements it; the kernel names only this. Every call is boot-, refresh- or setup-time, off the
/// request path, and blocks the calling thread up to its deadline.
pub trait SecretCalls: Send + Sync {
    /// `resolve` one reference's `settings` object (JSON bytes) to the secret's material. The
    /// plugin's lease is released before this returns; the material is held only in the
    /// [`Redacted`](crate::redacted::Redacted) it comes back in.
    ///
    /// # Errors
    /// The plugin's refusal, its code and its text.
    fn resolve(&self, settings: &[u8])
        -> Result<crate::redacted::Redacted<Vec<u8>>, SecretRefused>;
}

/// THE SECRET AXIS, as the composition root hands it to the kernel (ARCHITECT ruling Q8: the kernel
/// receives contract `<Kind>Axis` seams from the root, never the loader): every secret plugin the
/// root admitted, linked or dropped in, by the `module` a reference spells (its Statement name or an
/// alias). Installed once, in the root's rows; the kernel names nothing behind it.
pub trait SecretAxis: Send + Sync {
    /// Whether a secret plugin answers `module`, linked or dropped in.
    fn answers(&self, module: &str) -> bool;

    /// Whether `module` names a secret plugin this build LINKS (a reference to it needs no
    /// `secrets:` block and no plugins directory).
    fn linked(&self, module: &str) -> bool;

    /// The process's ONE instance of the linked plugin `module` names, opened on first use with no
    /// settings (a linked source takes no module-level configuration).
    ///
    /// # Errors
    /// No linked plugin answers `module`, or it will not load or open; the text names it.
    fn shared(&self, module: &str) -> Result<std::sync::Arc<dyn SecretCalls>, String>;

    /// OPEN a new instance of `module` over its module-level `settings` (as written: a secret
    /// reference stays a reference), each settings key its Statement names in `secret_refs`
    /// resolved through `resolve` and lent to `open` in that order. Closed when the last handle
    /// drops.
    ///
    /// # Errors
    /// No plugin answers `module`, a named secret reference does not resolve, or the plugin will not
    /// load or open; the text names it.
    fn open(
        &self,
        module: &str,
        settings: &serde_json::Value,
        resolve: &dyn Fn(&SecretRef) -> Result<Vec<u8>, String>,
    ) -> Result<std::sync::Arc<dyn SecretCalls>, String>;
}
