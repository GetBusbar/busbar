// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CORE WIPING BUFFER (TRANSPORT-TLS §2.0). Both legs queue credential-bearing bytes (request
//! heads with the injected `Authorization`, reply heads and bodies) in buffers that must not keep
//! what they release. [`SecureVec`] is a byte queue whose consumed prefix is wiped as it is
//! consumed, whose growth never reallocates live bytes in place, and whose allocation is
//! volatile-wiped before it is freed.
//!
//! Rules: (1) [`SecureVec::consume`] wipes `[head, head + n)` and advances `head`; nothing moves.
//! (2) Compaction only when new bytes do not fit after `end` and at least half the used span is
//! consumed; growth copies only `[head, end)` into a fresh zeroed block. (3) The read surface is
//! `[head, end)` only ([`SecureVec::as_slice`], `Deref` to `[u8]`); `Clone` copies the live bytes into a new
//! `SecureVec`; no `PartialEq`, and `Debug` prints the length. (4) No `realloc` of live bytes. (5) Hot wipes are a plain fill; the
//! volatile wipe runs on the free path and when a read loan is abandoned.
//!
//! SECURE-TYPES (core #164): the zeroize crate's wiping wrapper is banned in our code (LR-094). Secret memory
//! lives in one of three types, each built on the `zeroize` crate (`Zeroize` does the volatile
//! wipe; `ZeroizeOnDrop` marks that drop runs it) and none of which hands out a growable
//! `&mut Vec` or `&mut String`: [`SecureVec`] (secret bytes, fixed or growing), [`SecureString`]
//! (secret text) and [`SecureArray`] (fixed keys, seeds, digests). Growth always moves the live
//! bytes into a fresh block and wipes the old one. `Debug` prints the length only. The
//! connector's per-thread scratch slots over [`SecureVec`] live in
//! `busbar_core_connector::secure_vec`.

#![forbid(unsafe_code)]

use std::fmt;
#[cfg(test)]
use std::io;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(any(test, feature = "test-support"))]
pub use busbar_secure::{moved_bytes, refuse_growth, wipe_counts};
pub use busbar_secure::{Overflow, SecureVec, Tail};

/// Secret text: a `String` that never hands out `&mut String`, so it grows only through
/// [`SecureString::push_str`], which moves the text into a fresh block and wipes the old one.
/// Drop wipes the live text (adoption scrubbed the spare). `Debug` prints the length; there is no `Display`. Equality is
/// constant-time. `Clone` makes another `SecureString` (exact capacity), so no copy escapes custody.
#[derive(Default)]
pub struct SecureString(String);

impl SecureString {
    /// Empty; allocates nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self(String::new())
    }

    /// Empty, with room for `n` bytes before the first growth.
    #[must_use]
    pub fn with_capacity(n: usize) -> Self {
        Self(String::with_capacity(n))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Append `text`. When it does not fit, the held text moves into a fresh block of at least
    /// twice the capacity and the old block is wiped before it is freed.
    ///
    /// # Panics
    /// When the length overflows `usize` (as `String` growth does).
    pub fn push_str(&mut self, text: &str) {
        let len = self
            .0
            .len()
            .checked_add(text.len())
            .expect("secure text length");
        if len > self.0.capacity() {
            let mut next = String::with_capacity(len.max(self.0.capacity().saturating_mul(2)));
            next.push_str(&self.0);
            // Only `len` was ever written in the old block (adoption scrubbed its spare).
            let mut old = std::mem::replace(&mut self.0, next);
            old.as_mut_str().zeroize();
        }
        self.0.push_str(text);
    }

    /// Append one character.
    pub fn push(&mut self, c: char) {
        self.push_str(c.encode_utf8(&mut [0; 4]));
    }

    /// Text formatted straight into custody (the `format!` replacement): every growth on the way
    /// wipes the block it leaves.
    #[must_use]
    pub fn from_args(args: fmt::Arguments<'_>) -> Self {
        let mut s = Self::new();
        if let Some(text) = args.as_str() {
            s.push_str(text);
        } else {
            let _ = fmt::Write::write_fmt(&mut s, args);
        }
        s
    }

    /// The text as a plain `String`, without a copy. ONLY to hand it to another owner that wipes
    /// it (a field of a self-wiping struct): the `String` itself wipes nothing.
    #[must_use]
    pub fn into_string(mut self) -> String {
        std::mem::take(&mut self.0)
    }

    /// The room held before the next growth.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.0.capacity()
    }

    /// The text's bytes, without a copy, still in custody.
    #[must_use]
    pub fn into_bytes(mut self) -> SecureVec {
        SecureVec::from(std::mem::take(&mut self.0).into_bytes())
    }
}

/// Adopt `s` without a copy. Its spare capacity is volatile-wiped once (bytes a caller truncated
/// away), so drop and growth need wipe only `len`. Adopt only text built at its final size: a
/// `String` that grew before adoption already freed its old blocks unwiped (build it with
/// [`SecureString::from_args`] or `push_str` instead).
impl From<String> for SecureString {
    fn from(s: String) -> Self {
        if s.len() == s.capacity() {
            return Self(s);
        }
        let mut v = s.into_bytes();
        v.spare_capacity_mut().zeroize();
        Self(String::from_utf8(v).expect("adopted text stays UTF-8"))
    }
}

/// One exact copy of `s`.
impl From<&str> for SecureString {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl Clone for SecureString {
    fn clone(&self) -> Self {
        Self::from(self.as_str())
    }
}

impl std::ops::Deref for SecureString {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for SecureString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PartialEq for SecureString {
    fn eq(&self, other: &Self) -> bool {
        crate::constant_time_eq(self.0.as_bytes(), other.0.as_bytes())
    }
}

impl Eq for SecureString {}

impl fmt::Write for SecureString {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.push_str(s);
        Ok(())
    }
}

impl fmt::Debug for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureString")
            .field("len", &self.0.len())
            .finish()
    }
}

/// As a plain string (records that persist a secret today keep their shape).
impl serde::Serialize for SecureString {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

/// A plain string, adopted without a copy.
impl<'de> serde::Deserialize<'de> for SecureString {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        <String as serde::Deserialize>::deserialize(d).map(Self::from)
    }
}

impl Zeroize for SecureString {
    /// Volatile-wipe the text (only `len` was ever written) and hold none; the block is kept.
    fn zeroize(&mut self) {
        self.0.as_mut_str().zeroize();
        self.0.clear();
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        self.0.as_mut_str().zeroize();
    }
}

impl ZeroizeOnDrop for SecureString {}

/// A fixed-size secret (a key, a seed, a digest, a MAC). It never grows and is wiped on drop. No
/// `Clone`, no `Copy`: `*a` copies the array out, and only where the code means to.
#[repr(transparent)]
pub struct SecureArray<const N: usize>([u8; N]);

impl<const N: usize> SecureArray<N> {
    /// All zero.
    #[must_use]
    pub const fn zeroed() -> Self {
        Self([0; N])
    }
}

impl<const N: usize> Default for SecureArray<N> {
    fn default() -> Self {
        Self::zeroed()
    }
}

impl<const N: usize> From<[u8; N]> for SecureArray<N> {
    fn from(a: [u8; N]) -> Self {
        Self(a)
    }
}

impl<const N: usize> std::ops::Deref for SecureArray<N> {
    type Target = [u8; N];
    fn deref(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> std::ops::DerefMut for SecureArray<N> {
    fn deref_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> AsRef<[u8]> for SecureArray<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> PartialEq for SecureArray<N> {
    fn eq(&self, other: &Self) -> bool {
        crate::constant_time_eq(&self.0, &other.0)
    }
}

impl<const N: usize> Eq for SecureArray<N> {}

impl<const N: usize> fmt::Debug for SecureArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureArray").field("len", &N).finish()
    }
}

impl<const N: usize> Zeroize for SecureArray<N> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> Drop for SecureArray<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> ZeroizeOnDrop for SecureArray<N> {}
/// THE FREE-PATH WIPE of bytes held outside a `Secure*` type: volatile-zero every byte of
/// `bytes`, so no write is elided before the block is freed or handed on. The length is kept. A
/// `Vec<u8>` whose spare capacity also held secret bytes wipes with
/// [`crate::abi::sdk::wipe::wipe_bytes`].
pub fn wipe(bytes: &mut [u8]) {
    bytes.zeroize();
}

/// Volatile-zero `text`'s whole allocation (its spare capacity too) and empty it. The allocation
/// is kept.
pub fn wipe_string(text: &mut String) {
    text.zeroize();
}

#[cfg(test)]
#[path = "tests/secure_tests.rs"]
mod tests;
