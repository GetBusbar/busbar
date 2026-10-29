// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`Secret`] — the in-memory type for a RESOLVED secret VALUE (Part 2 #54, OWNER-LOCKED
//! 2026-09-20: "Secrets use a dedicated `Secret` type, not a bare string + lint").
//!
//! Every secret busbar resolves at boot and then HOLDS in memory — a `SecretRef` resolved to its
//! plaintext, an egress bearer/client-credentials/sigv4 secret, the admin token, a provider api_key,
//! the browser-login `client_secret`, and (1.5.2) a submitted credential password — is a
//! `Secret<T>`, so that:
//!
//! * **`Debug` / `Display` never reveal it.** Both print the literal `"[REDACTED]"`, byte for byte
//!   what 1.5.5's `Redacted` printed, so a log line reads as it did. A struct that embeds a `Secret`
//!   field and derives `Debug` therefore cannot leak the secret into a log line, a `tracing` field, a
//!   panic message, or an error `{:?}` — the redaction is STRUCTURAL, not a convention each call site
//!   must remember.
//! * **It does not serialize its plaintext.** `Secret` deliberately implements NEITHER `Serialize`
//!   NOR `Deserialize`. A secret held in engine memory therefore cannot be accidentally written into
//!   an audit record, a config dump, or any JSON payload.
//! * **It zeroizes its backing memory on drop.** `T: Zeroize`, so when a `Secret<String>` is
//!   dropped the heap bytes are overwritten rather than left in freed memory.
//! * **Its value is reached through ONE SEALED METHOD.** [`Secret::expose`] takes a
//!   [`KernelSeal`](crate::plugin::KernelSeal) — a `Pass` or a `Grant` the kernel minted (#40, #65)
//!   — so only host code the kernel lent a seal can read the plaintext. A plugin holds no seal and
//!   can implement none (the trait is sealed), so it cannot reach a secret's value by any path the
//!   type offers. There is no other raw accessor: the one crate-private read is this crate's own,
//!   where the SDK writes back a credential the plugin itself supplied.
//!
//! Every [`Secret::expose`] call site is an audit point where the secret escapes on purpose.
//!
//! **A PLUGIN'S OWN SECRET** (Part 2 #54, coordinator ruling on #1192: "the same type, not a new
//! one"). A plugin that holds secret material of its own (a minted token, a signing key) holds it
//! as the same `Secret`, under an OWNER: `Secret<T, Own>`, where `Own` is the plugin crate's own
//! seal, minted once by [`own_seal!`](crate::own_seal) as a crate-private type no other crate can
//! name or construct. [`Secret::held`] wraps the value and [`Secret::expose_own`] reads it under
//! that seal, so a plugin reads its own secret and no other: another crate's seal is another type
//! (a compile error), and the kernel's secrets ([`Kernel`], the default owner) offer no
//! `expose_own` at all. Everything else (the redaction, no serde, the zeroize on drop, the
//! constant-time equality) holds for every owner alike.

use core::fmt;
use core::marker::PhantomData;

use zeroize::Zeroize;

/// A resolved secret held in memory. `Debug`/`Display` print `"[REDACTED]"`; the value never
/// serializes; the backing memory is zeroized on drop; the value is read only through
/// [`Secret::expose`], under a kernel seal, or, for a plugin's own secret, [`Secret::expose_own`]
/// under its owner's seal. See the module docs. `Default` is an EMPTY secret (what a
/// `#[derive(Default)]` on a struct with a `Secret` field fills in): no material.
pub struct Secret<T: Zeroize, O = Kernel>(pub(crate) T, PhantomData<fn() -> O>);

/// The default OWNER of a [`Secret`]: the kernel. Uninhabited, and no [`OwnerSeal`]: a
/// kernel-owned secret is read only through [`Secret::expose`], under a kernel seal.
#[derive(Debug)]
pub enum Kernel {}

/// The supertrait that closes [`OwnerSeal`]: implemented only by [`own_seal!`](crate::own_seal)'s
/// expansion. Not part of the API.
#[doc(hidden)]
pub mod __owner {
    /// The closing supertrait.
    pub trait Minted {}
}

/// A plugin crate's OWN SEAL over the secrets it holds ([`Secret::held`], [`Secret::expose_own`]):
/// minted once per crate by [`own_seal!`](crate::own_seal), as a crate-private type with a private
/// constructor, so no other crate can name it, construct it, or read a secret it owns.
pub trait OwnerSeal: __owner::Minted {}

/// MINT THIS CRATE'S OWN SEAL ([`OwnerSeal`]): `busbar_contract::own_seal!(Own);` declares the
/// crate-private `Own`, its one constructor `Own::here()` (crate-private too), and its seal. A
/// secret the crate holds is then `Secret<T, Own>`: wrapped with [`Secret::held`], read with
/// [`Secret::expose_own`]`(&Own::here())`.
///
/// Another owner's seal cannot read it (a mismatched type):
///
/// ```compile_fail,E0308
/// mod a {
///     busbar_contract::own_seal!(Own);
///     pub(crate) fn key() -> busbar_contract::Secret<String, Own> {
///         busbar_contract::Secret::held(String::from("sk-own"))
///     }
/// }
/// mod b {
///     busbar_contract::own_seal!(Own);
/// }
/// let key = a::key();
/// let _ = key.expose_own(&b::Own::here());
/// ```
///
/// A kernel-owned secret offers no owner read:
///
/// ```compile_fail,E0599
/// mod a {
///     busbar_contract::own_seal!(Own);
/// }
/// let key = busbar_contract::Secret::new(String::from("sk-live"));
/// let _ = key.expose_own(&a::Own::here());
/// ```
///
/// and the seal is constructed only through its crate-private `here()`, never by its field:
///
/// ```compile_fail
/// mod a {
///     busbar_contract::own_seal!(Own);
/// }
/// let _ = a::Own(());
/// ```
#[macro_export]
macro_rules! own_seal {
    ($name:ident) => {
        /// This crate's own seal over the secrets it holds (`busbar_contract::OwnerSeal`).
        #[derive(Debug)]
        pub(crate) struct $name(());

        impl $name {
            /// The crate's seal: constructed only inside this crate.
            #[allow(dead_code)]
            pub(crate) const fn here() -> Self {
                Self(())
            }
        }

        impl $crate::redacted::__owner::Minted for $name {}
        impl $crate::redacted::OwnerSeal for $name {}
    };
}

impl<T: Zeroize + Default, O> Default for Secret<T, O> {
    fn default() -> Self {
        Self(T::default(), PhantomData)
    }
}

impl<T: Zeroize> Secret<T> {
    /// Wrap a resolved secret value.
    pub fn new(secret: T) -> Self {
        Self(secret, PhantomData)
    }

    /// Borrow the underlying secret: THE ONE RAW ACCESSOR, sealed (#54). `seal` is a kernel-minted
    /// `Pass` or `Grant` ([`KernelSeal`](crate::plugin::KernelSeal) is sealed to exactly those), so
    /// a caller that holds none cannot read the value. AUDIT POINT: every call site is a deliberate,
    /// reviewable place where the plaintext is used (a hop injection, an outbound credential, a
    /// constant-time compare, the single credential-transport wire boundary).
    ///
    /// Without a seal it does not compile:
    ///
    /// ```compile_fail,E0061
    /// let key = busbar_contract::Secret::new(String::from("sk-live"));
    /// let _ = key.expose();
    /// ```
    ///
    /// and the unsealed accessor it replaced is gone:
    ///
    /// ```compile_fail,E0599
    /// let key = busbar_contract::Secret::new(String::from("sk-live"));
    /// let _ = key.expose_secret();
    /// ```
    pub fn expose<S: crate::plugin::KernelSeal + ?Sized>(&self, _seal: &S) -> &T {
        &self.0
    }
}

/// THE HOST'S ZEROIZING BYTE HOLDER (the credential chip, row 6: host-owned secret bytes): a secret plugin
/// writes its resolved value straight into one ([`Secret::zeroed`], [`Secret::lend_mut`]); the
/// loader and the kernel keep the bytes in it, never in a `String`; it reaches a consumer's `open`
/// from here and is wiped when it drops.
impl Secret<Vec<u8>> {
    /// A zeroed holder of `cap` bytes, to lend a secret plugin's `resolve` as its buffer.
    #[must_use]
    pub fn zeroed(cap: usize) -> Self {
        Self(vec![0; cap], PhantomData)
    }

    /// The holder's buffer as a call lends it: its address and its length. Writing through it is
    /// the plugin's answer; reading it back is `unsafe` and reveals nothing [`Secret::expose`]
    /// would not.
    pub fn lend_mut(&mut self) -> (*mut u8, usize) {
        (self.0.as_mut_ptr(), self.0.len())
    }

    /// Keep the first `n` bytes, the value a plugin wrote: the bytes past them are wiped in place
    /// and the allocation is kept (no reallocation, so no copy of the value is left behind).
    pub fn keep(&mut self, n: usize) {
        let n = n.min(self.0.len());
        self.0[n..].zeroize();
        self.0.truncate(n);
    }

    /// The bytes as the UTF-8 text a text secret is, MOVED into a [`Secret<String>`] (the same
    /// allocation, never a copy), its trailing newline trimmed in place.
    ///
    /// # Errors
    /// [`NotText`]: the bytes are not UTF-8, or nothing is left after the trim. The bytes are
    /// wiped either way.
    pub fn into_text(mut self) -> Result<Secret<String>, NotText> {
        let bytes = core::mem::take(&mut self.0);
        let mut text = match String::from_utf8(bytes) {
            Ok(t) => Secret::new(t),
            Err(e) => {
                e.into_bytes().zeroize();
                return Err(NotText::NotUtf8);
            }
        };
        let kept = text.0.trim_end_matches(['\r', '\n']).len();
        // Cut in place: the trimmed newline stays in the allocation's spare capacity, which the
        // holder's drop wipes whole (`Vec::zeroize` zeroes the full capacity).
        text.0.truncate(kept);
        if text.0.is_empty() {
            return Err(NotText::Empty);
        }
        Ok(text)
    }
}

impl Secret<String> {
    /// The text's bytes, MOVED into a [`Secret<Vec<u8>>`] (the same allocation, never a copy).
    #[must_use]
    pub fn into_bytes(mut self) -> Secret<Vec<u8>> {
        Secret(core::mem::take(&mut self.0).into_bytes(), PhantomData)
    }
}

/// Why resolved bytes are not a text secret ([`Secret::into_text`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotText {
    /// The bytes are not UTF-8.
    NotUtf8,
    /// Nothing is left once the trailing newline is trimmed.
    Empty,
}

/// Every `Secret` wipes its value when it drops ([`Drop`] below): the marker a holder's type-level
/// check reads.
impl<T: Zeroize, O> zeroize::ZeroizeOnDrop for Secret<T, O> {}

/// A holder can be wiped before it drops (a lend that fails part-way wipes what it lent).
impl<T: Zeroize, O> Zeroize for Secret<T, O> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize, O: OwnerSeal> Secret<T, O> {
    /// Wrap a secret the plugin crate owning `O` holds itself.
    pub fn held(secret: T) -> Self {
        Self(secret, PhantomData)
    }

    /// Borrow a secret the caller's own crate holds, under that crate's seal: the owner reads its
    /// own secret and no other (another crate's seal is another type). AUDIT POINT, like
    /// [`Secret::expose`].
    pub fn expose_own(&self, _seal: &O) -> &T {
        &self.0
    }
}

impl<T: Zeroize> From<T> for Secret<T> {
    fn from(secret: T) -> Self {
        Self(secret, PhantomData)
    }
}

/// `Debug` NEVER reveals the secret — this is the core guarantee that makes redaction structural for
/// any struct that embeds a `Secret` field and derives `Debug`.
impl<T: Zeroize, O> fmt::Debug for Secret<T, O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// `Display` NEVER reveals the secret either (a `{}`-format into a log/message is just as leaky).
impl<T: Zeroize, O> fmt::Display for Secret<T, O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: Zeroize, O> Drop for Secret<T, O> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize + Clone, O> Clone for Secret<T, O> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), PhantomData)
    }
}

/// Equality on two secrets is CONSTANT-TIME. This type exists to make secret handling safe, and an
/// ordinary `==` on the plaintext (or a derived `PartialEq` on a struct that embeds a `Secret`
/// field — e.g. `ExchangeRequest`, `CompleteLogin`) would compare byte-by-byte with a data-dependent
/// early exit, leaking through timing how long a common prefix two secrets share. Routing through the
/// crate's [`constant_time_eq`](crate::constant_time_eq) — the same primitive the auth path uses to
/// compare credentials, here over its byte form — closes that channel for every secret comparison,
/// structurally. The bound is `AsRef<[u8]>`, satisfied by both shapes a secret is wrapped in: a
/// `String` (a token, a key) and a `Vec<u8>` (DER key material, a raw credential).
impl<T: Zeroize + AsRef<[u8]>, O> PartialEq for Secret<T, O> {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

impl<T: Zeroize + AsRef<[u8]>, O> Eq for Secret<T, O> {}

// ── The constant-time primitive `Secret`'s `PartialEq` is built on ───────────────────────────
//
// MOVED HERE VERBATIM from `busbar-api`'s `auth.rs` with `Secret` itself, because the two are one
// thing: `Secret`'s whole reason to exist is that comparing secrets must not leak through timing,
// and that guarantee IS this function. Leaving it behind would have meant a SECOND copy of a
// security primitive on the contract side — the exact shape the duplication census ranks above
// every other duplicate ("a duplicate that encodes a SECURITY or MONEY property outranks any
// duplicate that is merely bigger"). `busbar-api` re-exports it at its historical path.
//
// ITS SIBLING `sha256_hex` FOLLOWED IT (DECISIONS #83, ARCHITECT P68-0 residue (b)). It is
// `hex::encode(Sha256::digest(..))`, so it brings `sha2 -> cpufeatures -> libc` into the crate EVERY
// plugin links (#40(a)); the OWNER RULING of 2026-09-22 (the `(dep = libc, via = cpufeatures)` edge
// exemption in `qa/construction.toml`) settles that edge tree-wide as a CPU-capability query, not an
// I/O reach, so the digest now sits beside the compare it exists to feed and a plugin hashes both
// sides without naming `busbar-api`. `busbar-api` re-exports it at its historical path. This
// function itself still drags nothing: `core`/`std` only.

/// Constant-time comparison of the CONTENTS once lengths already match, to avoid leaking how much
/// of a token matches via timing. `#[inline(never)]` + `black_box` keep the optimizer from turning
/// the accumulation loop into an early-exit branch (which would reintroduce a timing signal for the
/// contents). The length check IS an early exit, and is only safe to apply to raw secret material
/// when the material's length is not itself sensitive — which a raw token generally is NOT expected
/// to be, but a caller comparing genuinely secret raw bytes directly (rather than through
/// `sha256_hex`) still leaks whether the two lengths matched. Prefer hashing both sides
/// first (see `sha256_hex`'s doc) so length never enters the comparison at all; this primitive alone
/// does not guarantee that for its caller.
///
/// Generic over any byte view (`str`, `String`, `[u8]`, `Vec<u8>`), so [`Secret`]'s `PartialEq`
/// (which also compares `Vec<u8>` secrets) runs this same loop: one constant-time primitive.
#[inline(never)]
pub fn constant_time_eq<A: AsRef<[u8]> + ?Sized, B: AsRef<[u8]> + ?Sized>(a: &A, b: &B) -> bool {
    let (a_bytes, b_bytes) = (a.as_ref(), b.as_ref());
    if a_bytes.len() != b_bytes.len() {
        return false;
    }

    // XOR all bytes and OR the results together. If any bit differs, result > 0.
    let mut result: u8 = 0;
    for (x, y) in a_bytes.iter().zip(b_bytes.iter()) {
        result |= x ^ y;
    }

    std::hint::black_box(result) == 0
}

/// Lowercase hex SHA-256 of `data` — THE digest facility credentials are compared under (a module
/// hashes both sides before [`constant_time_eq`]: every digest is 64 hex chars, so
/// `constant_time_eq`'s length early-exit never fires on a length difference driven by the raw
/// candidate, and candidate length leaks nothing). This is the pattern every auth module SHOULD
/// follow when comparing a caller-supplied credential against configured secret material — compare
/// raw only when the material's length is not itself sensitive.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(crate::abi::sdk::digest::sha256(data))
}

#[cfg(test)]
#[path = "tests/redacted_tests.rs"]
mod tests;

// The compile-time SERDE FENCE: pins `Secret<T>: !Serialize`/`!Deserialize` so a secret value can
// never reach an audit/wire/disk/log sink by construction (Part 3, Check 3 of the secret-hygiene design).
#[cfg(test)]
#[path = "tests/redacted_no_serde.rs"]
mod redacted_no_serde;
