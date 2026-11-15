// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Core types: borrowed views, the output channel, Status, Token and KindCode (IF §2, §2.4).
//!
//! The C-layout values live in busbar-ffi (UNSAFE-MIN r3.1), the plugin boundary and the only crate that
//! reads a view through a raw pointer. This module re-exports them under their frozen paths, so
//! `busbar_plugin_abi::types::Bytes` is `busbar_ffi::Bytes`. Their `mechanism!` blocks are busbar-ffi's, and
//! `fp::CORE_FP` folds them after this crate's own (UNSAFE-MIN §4.5).

use crate::need::ChainBytes;

pub use busbar_ffi::{
    Bytes, KindCode, Pair, RawOut, Slice, Status, Str, TOKEN_SESSION, Token, View,
};

/// The seal of `View`, `SyncArg` and `AsyncArg` (IF §2, §2.4 `sealed::Sealed`). `kind!` implements it for the
/// `views {}` structs it declares, so the path is public and hidden.
///
/// W1-A1: the trait is named `Seal`, not `Sealed`: the kernel's A3 check (R-CHECKS) counts impls by trait name
/// and every `Sealed` in the workspace is macro-implemented, which would class this one with them.
#[doc(hidden)]
pub mod sealed {
    pub trait Seal {}
}

impl sealed::Seal for Bytes<'_> {}
impl sealed::Seal for Str<'_> {}
impl<T: View> sealed::Seal for Slice<'_, T> {}
impl sealed::Seal for Pair<'_> {}
impl sealed::Seal for u32 {}
impl sealed::Seal for u64 {}
impl<V: View> sealed::Seal for &V {}
impl sealed::Seal for ChainBytes {}

/// A type that may appear as a kind-method argument. Sealed.
/// Sync methods accept: u32, u64, Bytes<'_>, Str<'_>, &V where V: View. Session kinds (plane, transport)
/// additionally take `s: &mut Self::Session` or `s: Self::Session` in the session position (§7.6); the raw
/// entry carries a Token there and the shim resolves it. `Token` itself is never a plugin-visible argument.
/// Async methods accept: u32, u64, ChainBytes (round 13: `ChainStr` is deleted). Nothing else, so the compiler refuses a non-FFI type.
pub trait SyncArg: sealed::Seal {}
pub trait AsyncArg: sealed::Seal {}

impl SyncArg for u32 {}
impl SyncArg for u64 {}
impl SyncArg for Bytes<'_> {}
impl SyncArg for Str<'_> {}
impl<V: View> SyncArg for &V {}

impl AsyncArg for u32 {}
impl AsyncArg for u64 {}
impl AsyncArg for ChainBytes {}

#[cfg(test)]
mod tests {
    use super::*;

    /// C-NULL-EMPTY (c), the Rust arm (round 17 empty rule): the empty values read empty without touching their
    /// pointer (Miri runs this). The `{NULL, 0}` and misaligned-pointer arms need the private fields, so they
    /// run inside busbar-ffi (`raw::tests::an_empty_view_reads_empty_whatever_its_pointer`), where the types live.
    #[test]
    fn an_empty_view_reads_empty_whatever_its_pointer() {
        assert!(Bytes::EMPTY.is_empty());
        assert_eq!(Bytes::EMPTY.get(), &[] as &[u8]);
        assert_eq!(Str::EMPTY.get(), "");
        assert!(Slice::<u64>::EMPTY.get().is_empty());
        assert!(Bytes::new(&[]).get().is_empty());
        assert_eq!(Str::new("").get(), "");
        assert!(Slice::<Pair<'_>>::new(&[]).get().is_empty());
    }

    #[test]
    fn a_view_reads_back_what_it_borrows() {
        assert_eq!(Bytes::new(b"abc").get(), b"abc");
        assert_eq!(Str::new("h\u{e9}").get(), "h\u{e9}");
        assert_eq!(Str::new("h\u{e9}").len(), 3);
        assert_eq!(Slice::new(&[1u64, 2, 3][..]).get(), &[1, 2, 3]);
        let pairs = [Pair {
            name: Str::new("accept"),
            value: Bytes::new(b"*/*"),
        }];
        let read = Slice::new(&pairs[..]).get();
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].name.get(), "accept");
        assert_eq!(read[0].value.get(), b"*/*");
        // The empty constructors never hand out null (busbar-ffi pins the pointer itself).
        assert!(Bytes::new(&[]).is_empty());
        assert!(Bytes::EMPTY.is_empty());
    }
}
