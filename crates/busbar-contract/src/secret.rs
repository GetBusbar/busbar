// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The SECRET-MODULE contract (`kind: secret` plugins). A secret module turns a config secret
//! reference's opaque `settings` into the secret BYTES: a source reads a process variable, a file,
//! a vault, a cloud secret manager or a database, each behind the plugin trust pipeline. The engine
//! sees only the contract - never the implementation - and treats every failure as FAIL-CLOSED (an
//! unresolvable secret refuses boot, never resolves empty).
//!
//! Moved here, module-path-only, from `busbar-api` (DECISIONS #83/#84; the per-kind trait is the
//! contract's, #35(a)). The error is [`SecretModuleError`] here because [`crate::kinds::SecretError`]
//! is a different type (#35 de-collision); its `Debug` keeps the historical `SecretError` label so
//! every rendering is byte-identical. Every source is an ordinary secret-kind plugin in its own repo
//! (THE DESIGN, "Plugins"), called through the secret kind table; the kernel reaches every loaded
//! secret plugin through [`SecretAxis`] and [`SecretCalls`], and reads the sugar each declares off
//! its Statement ([`SecretAxis::sugars`]). The [`SecretResolve`] seam followed the config secret
//! reference it takes into this crate once that reference merged here, when `busbar-api` retired.

use zeroize::Zeroize;

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
    ) -> SecretResult<Resolved<Vec<u8>>>;

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
    ) -> SecretResult<Resolved<Vec<u8>>> {
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
///
/// NO BARE VALUE CROSSES IT (Part 2 #54, owner-locked): every answer is a [`Resolved`], which the
/// asking owner seals to itself ([`Resolved::sealed_to`]) and then reads only through the sealed
/// accessor, so the owner that asked reads it and no other:
///
/// ```
/// use busbar_contract::secret::{Resolved, SecretResolve};
/// use busbar_contract::secret_ref::SecretRef;
/// struct One;
/// impl SecretResolve for One {
///     fn resolve(&self, _: &SecretRef) -> Result<Resolved<Vec<u8>>, String> {
///         Ok(Resolved::new(b"sk-live".to_vec()))
///     }
///     fn resolve_string(&self, _: &SecretRef) -> Result<Resolved<String>, String> {
///         Ok(Resolved::new(String::from("sk-live")))
///     }
/// }
/// mod a {
///     busbar_contract::own_seal!(Own);
/// }
/// let seam: &dyn SecretResolve = &One;
/// let key: busbar_contract::Secret<Vec<u8>, a::Own> =
///     seam.resolve(&SecretRef::none()).unwrap().sealed_to();
/// assert_eq!(key.expose_own(&a::Own::here()), b"sk-live");
/// ```
///
/// A value resolved for one owner is not exposed by another (a mismatched seal type):
///
/// ```compile_fail,E0308
/// use busbar_contract::secret::{Resolved, SecretResolve};
/// use busbar_contract::secret_ref::SecretRef;
/// struct One;
/// impl SecretResolve for One {
///     fn resolve(&self, _: &SecretRef) -> Result<Resolved<Vec<u8>>, String> {
///         Ok(Resolved::new(b"sk-live".to_vec()))
///     }
///     fn resolve_string(&self, _: &SecretRef) -> Result<Resolved<String>, String> {
///         Ok(Resolved::new(String::from("sk-live")))
///     }
/// }
/// mod a {
///     busbar_contract::own_seal!(Own);
/// }
/// mod b {
///     busbar_contract::own_seal!(Own);
/// }
/// let seam: &dyn SecretResolve = &One;
/// let key: busbar_contract::Secret<Vec<u8>, a::Own> =
///     seam.resolve(&SecretRef::none()).unwrap().sealed_to();
/// let _ = key.expose_own(&b::Own::here());
/// ```
///
/// and an answer offers no read of its own, sealed or not (its material is private):
///
/// ```compile_fail,E0616
/// use busbar_contract::secret::{Resolved, SecretResolve};
/// use busbar_contract::secret_ref::SecretRef;
/// struct One;
/// impl SecretResolve for One {
///     fn resolve(&self, _: &SecretRef) -> Result<Resolved<Vec<u8>>, String> {
///         Ok(Resolved::new(b"sk-live".to_vec()))
///     }
///     fn resolve_string(&self, _: &SecretRef) -> Result<Resolved<String>, String> {
///         Ok(Resolved::new(String::from("sk-live")))
///     }
/// }
/// let seam: &dyn SecretResolve = &One;
/// let _ = seam.resolve(&SecretRef::none()).unwrap().0;
/// ```
///
/// A kernel-owned answer is read only under a kernel seal, never under a plugin's own:
///
/// ```compile_fail,E0599
/// use busbar_contract::secret::{Resolved, SecretResolve};
/// use busbar_contract::secret_ref::SecretRef;
/// struct One;
/// impl SecretResolve for One {
///     fn resolve(&self, _: &SecretRef) -> Result<Resolved<Vec<u8>>, String> {
///         Ok(Resolved::new(b"sk-live".to_vec()))
///     }
///     fn resolve_string(&self, _: &SecretRef) -> Result<Resolved<String>, String> {
///         Ok(Resolved::new(String::from("sk-live")))
///     }
/// }
/// mod a {
///     busbar_contract::own_seal!(Own);
/// }
/// let seam: &dyn SecretResolve = &One;
/// let key = seam.resolve(&SecretRef::none()).unwrap().sealed();
/// let _ = key.expose_own(&a::Own::here());
/// ```
pub trait SecretResolve: Send + Sync {
    /// Resolve a reference to raw bytes (fail-closed). Some consumers — a raw-file loader, for
    /// instance — need the untrimmed bytes rather than a string.
    fn resolve(&self, secret: &SecretRef) -> Result<Resolved<Vec<u8>>, String>;

    /// Resolve a reference to a UTF-8 STRING (trailing newline trimmed; fail-closed on non-UTF-8 or
    /// empty). Some consumers — a credential-minting path, for instance — need the string form.
    fn resolve_string(&self, secret: &SecretRef) -> Result<Resolved<String>, String>;

    /// [`Self::resolve`] at CONFIG TIME, with its proof: the one way a reference to a source that
    /// reads the disk resolves (THE DESIGN Q-DISK R4, OWNER 2026-10-13). Every other source answers
    /// exactly as [`Self::resolve`] does.
    fn resolve_at_config(
        &self,
        secret: &SecretRef,
        _scope: &crate::config_time::ConfigScope,
    ) -> Result<Resolved<Vec<u8>>, String> {
        self.resolve(secret)
    }

    /// [`Self::resolve_string`] at CONFIG TIME, with its proof (see [`Self::resolve_at_config`]).
    fn resolve_string_at_config(
        &self,
        secret: &SecretRef,
        _scope: &crate::config_time::ConfigScope,
    ) -> Result<Resolved<String>, String> {
        self.resolve_string(secret)
    }
}

/// WHAT THE SEAM ANSWERS ([`SecretResolve`], [`SecretAxis::open`]'s resolver, [`SecretModule`]): a
/// resolved secret's material, held for the owner that asked. It offers NO read of its own: the
/// asker seals it to itself ([`Resolved::sealed_to`] for a plugin crate's own seal,
/// [`Resolved::sealed`] for the kernel) and reads the [`Secret`](crate::redacted::Secret) that
/// comes back through that owner's one sealed accessor. `Debug` prints `[REDACTED]`, nothing
/// serializes it, and its memory is zeroized on drop, exactly as a `Secret`'s.
pub struct Resolved<T: Zeroize + Default>(pub(crate) T);

impl<T: Zeroize + Default> Resolved<T> {
    /// The material a source resolved, as the seam answers it.
    pub fn new(material: T) -> Self {
        Self(material)
    }

    /// A kernel-owned secret handed across the seam, under the kernel seal that may read it: its
    /// material moves (never copied out in the clear) into the answer.
    pub fn of_kernel<S: crate::plugin::KernelSeal + ?Sized>(
        secret: crate::redacted::Secret<T>,
        _seal: &S,
    ) -> Self {
        let mut secret = secret;
        Self(core::mem::take(&mut secret.0))
    }

    /// SEAL the answer to the asking owner `O` (a plugin crate's own seal, [`own_seal!`](crate::own_seal)):
    /// the one way out of it. The material moves into the `Secret`, which only `O` reads.
    pub fn sealed_to<O>(mut self) -> crate::redacted::Secret<T, O> {
        crate::redacted::Secret::owned(core::mem::take(&mut self.0))
    }

    /// Whether the answer holds no material at all: what a fail-closed caller refuses, read
    /// without the material ever leaving the seal.
    pub fn is_empty(&self) -> bool
    where
        T: AsRef<[u8]>,
    {
        self.0.as_ref().is_empty()
    }

    /// SEAL the answer to the kernel ([`Kernel`](crate::redacted::Kernel)): read only under a
    /// kernel seal ([`Secret::expose`](crate::redacted::Secret::expose)).
    pub fn sealed(self) -> crate::redacted::Secret<T> {
        self.sealed_to()
    }
}

/// Why resolved bytes are not the text a text secret is ([`Resolved::into_text`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotText {
    /// The bytes are not UTF-8.
    NotUtf8,
    /// Nothing is left once the trailing newlines are trimmed.
    Empty,
}

impl Resolved<Vec<u8>> {
    /// The answer as the UTF-8 TEXT a text secret is: trailing `\r` / `\n` trimmed, refused when
    /// the bytes are not UTF-8 or nothing is left. The material never leaves the seal: what is not
    /// kept is zeroized here.
    ///
    /// # Errors
    /// [`NotText`]: not UTF-8, or empty once trimmed.
    pub fn into_text(mut self) -> Result<Resolved<String>, NotText> {
        let bytes = core::mem::take(&mut self.0);
        let mut text = match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(e) => {
                e.into_bytes().zeroize();
                return Err(NotText::NotUtf8);
            }
        };
        let kept = text.trim_end_matches(['\r', '\n']).len();
        if kept == 0 {
            text.zeroize();
            return Err(NotText::Empty);
        }
        let mut tail = text.split_off(kept);
        tail.zeroize();
        Ok(Resolved(text))
    }
}

impl Resolved<String> {
    /// The text answer as its bytes, still sealed (the material moves; nothing is copied out).
    pub fn into_bytes(mut self) -> Resolved<Vec<u8>> {
        Resolved(core::mem::take(&mut self.0).into_bytes())
    }
}

impl<T: Zeroize + Default> core::fmt::Debug for Resolved<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: Zeroize + Default> Drop for Resolved<T> {
    fn drop(&mut self) {
        self.0.zeroize();
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
/// secret resolution crosses the secret kind table through the one dispatcher). The plugin loader
/// implements it; the kernel names only this. Every call is boot-, refresh- or setup-time, off the
/// request path, and blocks the calling thread up to its deadline.
pub trait SecretCalls: Send + Sync {
    /// `resolve` one reference's `settings` object (JSON bytes) to the secret's material. The
    /// plugin's lease is released before this returns; the material is held only in the
    /// [`Secret`](crate::redacted::Secret) it comes back in.
    ///
    /// # Errors
    /// The plugin's refusal, its code and its text.
    fn resolve(&self, settings: &[u8]) -> Result<crate::redacted::Secret<Vec<u8>>, SecretRefused>;

    /// `resolve` at CONFIG TIME, with its proof ([`ConfigScope`](crate::config_time::ConfigScope)):
    /// the one way a source that reads the disk resolves (THE DESIGN Q-DISK R4, OWNER 2026-10-13).
    /// Every other source answers exactly as [`Self::resolve`] does.
    ///
    /// # Errors
    /// The plugin's refusal, its code and its text.
    fn resolve_at_config(
        &self,
        settings: &[u8],
        _scope: &crate::config_time::ConfigScope,
    ) -> Result<crate::redacted::Secret<Vec<u8>>, SecretRefused> {
        self.resolve(settings)
    }
}

/// THE SECRET AXIS, as the composition root hands it to the kernel (ARCHITECT ruling Q8: the kernel
/// receives contract `<Kind>Axis` seams from the root, never the loader): every secret plugin the
/// root admitted, linked or dropped in, by the `module` a reference spells (its Statement name or an
/// alias). Installed once, in the root's rows; the kernel names nothing behind it.
pub trait SecretAxis: Send + Sync {
    /// The SUGARS the admitted secret plugins' Statements declare (owner law 2026-09-27: the
    /// kernel resolves the sugar generically, from what the plugins declare): what the host reads
    /// its configuration's secret references against.
    fn sugars(&self) -> crate::secret_ref::Sugars;

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
        resolve: &dyn Fn(&SecretRef) -> Result<Resolved<Vec<u8>>, String>,
    ) -> Result<std::sync::Arc<dyn SecretCalls>, String>;
}
