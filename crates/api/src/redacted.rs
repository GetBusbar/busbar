// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`Redacted`] — the in-memory wrapper for a RESOLVED secret VALUE.
//!
//! Every secret busbar resolves at boot and then HOLDS in memory — a `SecretRef` resolved to its
//! plaintext, an egress bearer/client-credentials/sigv4 secret, the admin token, a provider api_key,
//! the browser-login `client_secret`, and (1.5.2) a submitted credential password — is wrapped in
//! `Redacted<T>` so that:
//!
//! * **`Debug` / `Display` never reveal it.** Both print the literal `"[REDACTED]"`. A struct that
//!   embeds a `Redacted` field and derives `Debug` therefore cannot leak the secret into a log line,
//!   a `tracing` field, a panic message, or an error `{:?}` — the redaction is STRUCTURAL, not a
//!   convention each call site must remember.
//! * **It does not serialize its plaintext.** `Redacted` deliberately implements NEITHER `Serialize`
//!   NOR `Deserialize`. A secret held in engine memory therefore cannot be accidentally written into
//!   an audit record, a config dump, or any JSON payload. The ONE place a resolved credential must
//!   legitimately cross a boundary — the `complete_login` FFI call that hands a submitted credential
//!   to the auth plugin that will verify it — does so through a plain `String` field on the WIRE type
//!   (`busbar_plugin::cold::auth::CompleteLoginRequest.submitted`), an explicit, documented, single
//!   plaintext boundary, converted from `Redacted` via [`Redacted::expose_secret`]. There is no
//!   implicit serialization path.
//! * **It zeroizes its backing memory on drop.** `T: Zeroize`, so when a `Redacted<String>` is
//!   dropped the heap bytes are overwritten rather than left in freed memory.
//!
//! Reaching the underlying value is done ONLY through [`Redacted::expose_secret`] — every call site is
//! an audit point where the secret escapes redaction on purpose.

use core::fmt;

use zeroize::Zeroize;

/// A resolved secret held in memory. `Debug`/`Display` print `"[REDACTED]"`; the value never
/// serializes; the backing memory is zeroized on drop. See the module docs.
pub struct Redacted<T: Zeroize>(T);

impl<T: Zeroize> Redacted<T> {
    /// Wrap a resolved secret value.
    pub fn new(secret: T) -> Self {
        Self(secret)
    }

    /// Borrow the underlying secret. AUDIT POINT: the value escapes redaction here — every call site
    /// is a deliberate, reviewable place where the plaintext is used (a hop injection, an outbound
    /// credential, a constant-time compare, the single credential-transport wire boundary).
    pub fn expose_secret(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> From<T> for Redacted<T> {
    fn from(secret: T) -> Self {
        Self(secret)
    }
}

/// `Debug` NEVER reveals the secret — this is the core guarantee that makes redaction structural for
/// any struct that embeds a `Redacted` field and derives `Debug`.
impl<T: Zeroize> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// `Display` NEVER reveals the secret either (a `{}`-format into a log/message is just as leaky).
impl<T: Zeroize> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: Zeroize> Drop for Redacted<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize + Clone> Clone for Redacted<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Equality on two secrets is CONSTANT-TIME. This type exists to make secret handling safe, and an
/// ordinary `==` on the plaintext (or a derived `PartialEq` on a struct that embeds a `Redacted`
/// field — e.g. `ExchangeRequest`, `CompleteLogin`) would compare byte-by-byte with a data-dependent
/// early exit, leaking through timing how long a common prefix two secrets share. Routing through the
/// crate's [`constant_time_eq`](crate::constant_time_eq) — the same primitive the auth path uses to
/// compare credentials — closes that channel for every secret comparison, structurally. The bound is
/// `AsRef<str>` (satisfied by `String`, the only `T` any secret is wrapped in) so the comparison can
/// go through that str-based primitive.
impl<T: Zeroize + AsRef<str>> PartialEq for Redacted<T> {
    fn eq(&self, other: &Self) -> bool {
        crate::auth::constant_time_eq(self.0.as_ref(), other.0.as_ref())
    }
}

impl<T: Zeroize + AsRef<str>> Eq for Redacted<T> {}

#[cfg(test)]
#[path = "tests/redacted_tests.rs"]
mod tests;

// The compile-time SERDE FENCE: pins `Redacted<T>: !Serialize`/`!Deserialize` so a secret value can
// never reach an audit/wire/disk/log sink by construction (Part 3, Check 3 of the secret-hygiene design).
#[cfg(test)]
#[path = "tests/redacted_no_serde.rs"]
mod redacted_no_serde;
