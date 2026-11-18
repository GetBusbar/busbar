// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`Secret`] — the in-memory type for a RESOLVED secret VALUE (Part 2 #54, OWNER-LOCKED

use core::fmt;
use core::marker::PhantomData;

use zeroize::Zeroize;

/// A resolved secret held in memory. `Debug`/`Display` print `"[REDACTED]"`; the value never
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

    /// The value MOVED out (the same allocation, never a copy), sealed as [`Secret::expose`] is:
    pub fn into_exposed<S: crate::plugin::KernelSeal + ?Sized>(mut self, _seal: &S) -> T
    where
        T: Default,
    {
        core::mem::take(&mut self.0)
    }
}

/// THE HOST'S ZEROIZING BYTE HOLDER: a secret plugin
impl Secret<Vec<u8>> {
    /// A zeroed holder of `cap` bytes, to lend a secret plugin's `resolve` as its buffer.
    #[must_use]
    pub fn zeroed(cap: usize) -> Self {
        Self(vec![0; cap], PhantomData)
    }

    /// The holder's buffer as a call lends it: its address and its length. Writing through it is
    pub fn lend_mut(&mut self) -> (*mut u8, usize) {
        (self.0.as_mut_ptr(), self.0.len())
    }

    /// Replace the held bytes with `bytes`: the old ones are wiped first and the allocation is
    /// reused (it grows only when `bytes` is longer than any value it held).
    pub fn refill(&mut self, bytes: &[u8]) {
        self.0.zeroize();
        self.0.extend_from_slice(bytes);
    }

    /// Keep the first `n` bytes, the value a plugin wrote: the bytes past them are wiped in place
    pub fn keep(&mut self, n: usize) {
        let n = n.min(self.0.len());
        self.0[n..].zeroize();
        self.0.truncate(n);
    }

    /// The bytes as the UTF-8 text a text secret is, MOVED into a [`Secret<String>`] (the same
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
impl<T: Zeroize + AsRef<[u8]>, O> PartialEq for Secret<T, O> {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

impl<T: Zeroize + AsRef<[u8]>, O> Eq for Secret<T, O> {}

/// ONE SECRET, SHARED (SINGLE-PATH SP-AU6): one [`Secret<Vec<u8>, O>`] that every holder shares.
/// Cloning a handle clones an [`Arc`](std::sync::Arc), never the bytes, so the plaintext lives in
/// exactly one heap buffer until the last handle drops; then `Secret`'s own [`Drop`] wipes it,
/// once. The handle itself wipes nothing, so this type does not claim [`zeroize::ZeroizeOnDrop`].
///
/// It is read only as [`Secret`] is, through the same seals: [`SharedSecret::expose`] under a
/// kernel seal, [`SharedSecret::expose_own`] under its owner's. No API returns the inner `Secret`
/// or an owned value, and the value is never mutated: a byte copy is an explicit `to_vec` after a
/// sealed `expose`, a reviewable audit point. [`SharedSecret::ptr_eq`] checks custody without
/// reading a byte.
///
/// Without a seal it does not compile:
///
/// ```compile_fail,E0061
/// let shared = busbar_contract::Secret::new(b"sk-live".to_vec()).share();
/// let _ = shared.expose();
/// ```
pub struct SharedSecret<O = Kernel>(std::sync::Arc<Secret<Vec<u8>, O>>);

impl<O> Secret<Vec<u8>, O> {
    /// The value MOVED into one [`SharedSecret`] (the same allocation, never a copy).
    #[must_use]
    pub fn share(self) -> SharedSecret<O> {
        SharedSecret(std::sync::Arc::new(self))
    }
}

impl SharedSecret {
    /// Borrow the shared bytes under a kernel seal, exactly as [`Secret::expose`]: AUDIT POINT.
    pub fn expose<S: crate::plugin::KernelSeal + ?Sized>(&self, seal: &S) -> &Vec<u8> {
        self.0.expose(seal)
    }
}

impl<O: OwnerSeal> SharedSecret<O> {
    /// Borrow the shared bytes under their owner's seal, exactly as [`Secret::expose_own`].
    pub fn expose_own(&self, seal: &O) -> &Vec<u8> {
        self.0.expose_own(seal)
    }
}

impl<O> SharedSecret<O> {
    /// Whether `a` and `b` share one buffer: a custody check that reads no bytes.
    #[must_use]
    pub fn ptr_eq(a: &Self, b: &Self) -> bool {
        std::sync::Arc::ptr_eq(&a.0, &b.0)
    }
}

/// Another handle on the same buffer: an `Arc` clone, never a byte copy.
impl<O> Clone for SharedSecret<O> {
    fn clone(&self) -> Self {
        Self(std::sync::Arc::clone(&self.0))
    }
}

/// Bytes MOVED into one shared kernel-owned buffer (the same allocation, never a copy), as
/// [`Secret`]'s own `From` moves them.
impl From<Vec<u8>> for SharedSecret {
    fn from(bytes: Vec<u8>) -> Self {
        Secret::new(bytes).share()
    }
}

/// An empty buffer (a passthrough lend with no caller credential).
impl<O> Default for SharedSecret<O> {
    fn default() -> Self {
        Secret::<Vec<u8>, O>::default().share()
    }
}

/// `Debug` NEVER reveals the secret, as [`Secret`]'s does not.
impl<O> fmt::Debug for SharedSecret<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// `Display` NEVER reveals the secret either.
impl<O> fmt::Display for SharedSecret<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// DEV-ONLY (`stage-probe`): whether a [`SharedSecret`]'s one buffer has been released, its last
/// handle dropped. It holds no handle and offers no read, so it can neither keep the buffer alive
/// nor reach its bytes. It proves release only; the wipe on release is `Secret`'s own [`Drop`].
#[cfg(feature = "stage-probe")]
pub struct SharedSecretWatch<O = Kernel>(std::sync::Weak<Secret<Vec<u8>, O>>);

#[cfg(feature = "stage-probe")]
impl<O> SharedSecret<O> {
    /// DEV-ONLY (`stage-probe`): watch this buffer's release.
    #[must_use]
    pub fn watch(&self) -> SharedSecretWatch<O> {
        SharedSecretWatch(std::sync::Arc::downgrade(&self.0))
    }
}

#[cfg(feature = "stage-probe")]
impl<O> SharedSecretWatch<O> {
    /// Whether every handle on the watched buffer has dropped.
    #[must_use]
    pub fn released(&self) -> bool {
        self.0.strong_count() == 0
    }
}

#[cfg(feature = "stage-probe")]
impl<O> fmt::Debug for SharedSecretWatch<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedSecretWatch")
            .field("released", &self.released())
            .finish()
    }
}

/// A FINGERPRINT of held material, for "did it change" only: SHA-256 keyed with a per-process
/// random key over each part's length and bytes. An unsalted digest of a low-entropy credential is
/// an offline oracle if it ever reaches a log or a dump; a keyed one is not. Compare two with
/// [`constant_time_eq`], and never derive `Debug` over one. The process stops (exit 2) if the OS
/// random source cannot key it.
#[must_use]
pub fn fingerprint<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> [u8; 32] {
    static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    let key = KEY.get_or_init(|| {
        let mut key = [0_u8; 32];
        if crate::crypto::fill(&mut key).is_err() {
            eprintln!("busbar: the OS random source did not answer; held material cannot be fingerprinted");
            std::process::exit(2);
        }
        key
    });
    let mut hash = crate::crypto::Sha256::new();
    hash.update(key);
    for part in parts {
        hash.update(&(part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    hash.finish()
}

/// Constant-time comparison of the CONTENTS once lengths already match, to avoid leaking how much
#[inline(never)]
pub fn constant_time_eq<A: AsRef<[u8]> + ?Sized, B: AsRef<[u8]> + ?Sized>(a: &A, b: &B) -> bool {
    let (a_bytes, b_bytes) = (a.as_ref(), b.as_ref());
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    subtle::ConstantTimeEq::ct_eq(a_bytes, b_bytes).into()
}

/// Lowercase hex SHA-256 of `data` — THE digest facility credentials are compared under (a module
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(crate::abi::sdk::digest::sha256(data))
}

#[cfg(test)]
#[path = "tests/redacted_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/redacted_no_serde.rs"]
mod redacted_no_serde;
