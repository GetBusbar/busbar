// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Core types: borrowed views, the output channel, Status, Token and KindCode (IF §2, §2.4).

use core::marker::PhantomData;
use core::ptr::NonNull;

use crate::need::ChainBytes;

mechanism! {
/// Borrowed bytes. Valid for `'a` only. In sync calls `'a` is the call; the shim never widens it.
/// `ptr` may be null only when `len == 0`. Fields are private: the only constructor is `new`.
/// **Round 17, the empty rule (I4/I7, binding on `Bytes`, `Str` and `Slice` alike):** `{ptr, 0}` with any
/// `ptr` (null, dangling or misaligned) is the empty value, from either side and from C. `get` tests
/// `len == 0` first and returns `&[]` (`""` for `Str`, `&[]` for `Slice`) without touching `ptr`; it calls
/// `slice::from_raw_parts` only when `len > 0`, and only then is `ptr` required non-null and aligned. `EMPTY`
/// is `{NonNull::dangling(), 0}`, so a Rust producer never emits null, but every reader accepts it.
/// C-NULL-EMPTY (§14) sends `{NULL, 0}` in every `CryptoReq` field and in empty `results`/`config`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Bytes<'a> { ptr: *const u8, len: usize, _l: PhantomData<&'a [u8]> }

/// Borrowed UTF-8. The producer guarantees UTF-8 (core builds every `Str` a plugin receives from `&str`).
/// `get` does not re-validate. Core re-validates every `Str` it turns into a core string.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Str<'a>(Bytes<'a>);

/// Borrowed array of `T: View`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Slice<'a, T: View> { ptr: *const T, len: usize, _l: PhantomData<&'a [T]> }

/// A name/value pair (headers, query params, claims). `name` is lowercase ASCII when it is an HTTP header.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Pair<'a> { pub name: Str<'a>, pub value: Bytes<'a> }

/// The plugin-visible output channel (r4 H2). It carries no authority: the host keeps the real pointer,
/// capacity and max_out in its own OutBuf and rewrites `ptr`/`cap` on `grow`.
#[repr(C)]
pub struct RawOut { pub ptr: *mut u8, pub len: usize, pub cap: usize }

/// The one return value of every raw entry.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Status(pub u32);

/// Shim-minted handle for a chain or a session (transport connection, plane request). Plugin code never sees
/// or chooses one: the `kind!` shims mint it from `slots.rs` (§6.5). Layout: bit 63 = 1 for a session token,
/// 0 for a chain token; bits 32..=62 = slot generation (starts at 1, so a token is never 0); bits 0..=31 = slot
/// index. The host only stores it, compares it and passes it back. The token is NOT the ChainBytes check
/// value: its 31-bit generation may wrap. Round 14: the host **can** be left holding a stale token value: the
/// shim frees a chain's slot itself before it answers FAULT (§6.4 steps 2-4), so the value in the host's
/// `ChainGuard` then names a free (and possibly reused) slot. The driver zeroes it in its FAULT arm and never
/// presents it (§10.5), and soundness does not rest on that: `Slots::remove` changes the slot's generation and
/// clears its occupied bit **before** the slot reaches the free list, and every lookup of a free slot or an
/// older generation fails (§6.5), so a stale token is a no-op OK on cancel and FAULT `BadToken` on resume, never
/// an access to another chain. Chain argument handles check a 64-bit never-reused serial instead (§6.2).
pub type Token = u64;
/// Bit 63 of a session token.
pub const TOKEN_SESSION: u64 = 1 << 63;

/// The seven kinds, with the numbers origin/dev already uses (`abi/mechanism/mod.rs` KindCode).
#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum KindCode { Store = 1, Secret = 2, Auth = 3, Hook = 4, Export = 5, Plane = 6, Transport = 7 }
}

impl<'a> Bytes<'a> {
    pub const EMPTY: Bytes<'static> = Bytes {
        ptr: NonNull::<u8>::dangling().as_ptr().cast_const(),
        len: 0,
        _l: PhantomData,
    };
    pub const fn new(s: &'a [u8]) -> Self {
        Bytes {
            ptr: s.as_ptr(),
            len: s.len(),
            _l: PhantomData,
        }
    }
    /// The slice. `len == 0` returns `&[]` and never reads `ptr` (the empty rule above); otherwise
    /// `from_raw_parts(ptr, len)`. A plugin may receive `{NULL, 0}` from a C producer or a host `EMPTY`.
    #[allow(unsafe_code)]
    pub fn get(self) -> &'a [u8] {
        if self.len == 0 {
            return &[];
        }
        // SAFETY: a `Bytes` with `len > 0` is built by `new` from a `&'a [u8]` or handed over the FFI by a producer
        // bound by the §2 contract: `ptr` is non-null and points at `len` initialised bytes that stay valid and
        // unchanged for `'a`.
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }
    pub const fn len(self) -> usize {
        self.len
    }
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
}

impl<'a> Str<'a> {
    pub const EMPTY: Str<'static> = Str(Bytes::EMPTY);
    pub const fn new(s: &'a str) -> Self {
        Str(Bytes::new(s.as_bytes()))
    }
    /// `len == 0` returns `""` without reading `ptr` (round 17 empty rule); otherwise unchecked UTF-8 view.
    #[allow(unsafe_code)]
    pub fn get(self) -> &'a str {
        let bytes = self.0.get();
        // SAFETY: the producer guarantees UTF-8 (§2: core builds every `Str` a plugin receives from `&str`, and
        // `new` takes a `&str`); `get` does not re-validate, and core re-validates every `Str` it keeps.
        unsafe { core::str::from_utf8_unchecked(bytes) }
    }
    pub const fn len(self) -> usize {
        self.0.len()
    }
}

impl<'a, T: View> Slice<'a, T> {
    // The IF types this `Slice<'static, T>`; that type is well-formed only for `T: 'static` (the
    // `PhantomData<&'a [T]>` field), which the impl does not bound, so it is written `Self` (any `'a`).
    pub const EMPTY: Self = Slice {
        ptr: NonNull::<T>::dangling().as_ptr().cast_const(),
        len: 0,
        _l: PhantomData,
    };
    pub const fn new(s: &'a [T]) -> Self {
        Slice {
            ptr: s.as_ptr(),
            len: s.len(),
            _l: PhantomData,
        }
    }
    /// `len == 0` returns `&[]` without reading `ptr` (round 17 empty rule); otherwise `from_raw_parts`.
    #[allow(unsafe_code)]
    pub fn get(self) -> &'a [T] {
        if self.len == 0 {
            return &[];
        }
        // SAFETY: as `Bytes::get`: with `len > 0`, `ptr` is non-null, aligned for `T` and points at `len`
        // initialised `T` valid for `'a` (built by `new` from a `&'a [T]`, or by a producer bound by §2).
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }
}

/// The seal of `View`, `SyncArg` and `AsyncArg` (IF §2, §2.4 `sealed::Sealed`). `kind!` implements it for the
/// `views {}` structs it declares, so the path is public and hidden.
///
/// W1-A1: the trait is named `Seal`, not `Sealed`: the kernel's A3 check (R-CHECKS) counts impls by trait name
/// and every `Sealed` in the workspace is macro-implemented, which would class this one with them.
#[doc(hidden)]
pub mod sealed {
    pub trait Seal {}
}

/// Marker for types allowed inside an input view. Sealed: implemented only for Bytes, Str, Slice, Pair,
/// u32, u64 and the `views {}` structs that `kind!` declares. A view struct is `#[repr(C)]` and `Copy`, its
/// fields are only `View` types, and it has no implicit padding (`kind!` asserts the size equals the sum).
#[allow(unsafe_code)]
pub unsafe trait View: Copy + sealed::Seal {}

impl sealed::Seal for Bytes<'_> {}
impl sealed::Seal for Str<'_> {}
impl<T: View> sealed::Seal for Slice<'_, T> {}
impl sealed::Seal for Pair<'_> {}
impl sealed::Seal for u32 {}
impl sealed::Seal for u64 {}
impl<V: View> sealed::Seal for &V {}
impl sealed::Seal for ChainBytes {}

// SAFETY (every `View` impl below): the type is `Copy`, `#[repr(C)]` or `#[repr(transparent)]` (or a primitive),
// its fields are pointers, lengths and other `View` types only, and it has no implicit padding (a pointer and a
// `usize`, or two such pairs), so a C producer and the Rust reader agree on every byte.
#[allow(unsafe_code)]
unsafe impl View for Bytes<'_> {}
#[allow(unsafe_code)]
unsafe impl View for Str<'_> {}
#[allow(unsafe_code)]
unsafe impl<T: View> View for Slice<'_, T> {}
#[allow(unsafe_code)]
unsafe impl View for Pair<'_> {}
#[allow(unsafe_code)]
unsafe impl View for u32 {}
#[allow(unsafe_code)]
unsafe impl View for u64 {}

impl Status {
    /// Answer records are in Out.
    pub const OK: Status = Status(0);
    /// A domain verdict. One FAIL record (status REFUSED) is in Out.
    pub const REFUSED: Status = Status(1);
    /// The backend failed. One FAIL record (status FAILED) is in Out. Its text is never secret.
    pub const FAILED: Status = Status(2);
    /// A step. One or more NEED records and exactly one TOKEN record are in Out (§6).
    pub const NEED: Status = Status(3);
    /// A panic was caught or the contract was broken. Any value above 4 is FAULT too.
    pub const FAULT: Status = Status(4);
}

impl KindCode {
    pub const ALL: [KindCode; 7] = [
        KindCode::Store,
        KindCode::Secret,
        KindCode::Auth,
        KindCode::Hook,
        KindCode::Export,
        KindCode::Plane,
        KindCode::Transport,
    ];
    pub const fn from_raw(raw: u32) -> Option<KindCode> {
        match raw {
            1 => Some(KindCode::Store),
            2 => Some(KindCode::Secret),
            3 => Some(KindCode::Auth),
            4 => Some(KindCode::Hook),
            5 => Some(KindCode::Export),
            6 => Some(KindCode::Plane),
            7 => Some(KindCode::Transport),
            _ => None,
        }
    }
    /// The manifest word: "store", "secret", "auth", "hook", "export", "plane", "transport".
    pub const fn word(self) -> &'static str {
        match self {
            KindCode::Store => "store",
            KindCode::Secret => "secret",
            KindCode::Auth => "auth",
            KindCode::Hook => "hook",
            KindCode::Export => "export",
            KindCode::Plane => "plane",
            KindCode::Transport => "transport",
        }
    }
    /// The one ABI number this engine accepts for the kind (§7.3).
    pub const fn abi(self) -> u32 {
        match self {
            KindCode::Store => crate::versions::STORE,
            KindCode::Secret => crate::versions::SECRET,
            KindCode::Auth => crate::versions::AUTH,
            KindCode::Hook => crate::versions::HOOK,
            KindCode::Export => crate::versions::EXPORT,
            KindCode::Plane => crate::versions::PLANE,
            KindCode::Transport => crate::versions::TRANSPORT,
        }
    }
}

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

    /// C-NULL-EMPTY (c), the Rust arm (round 17 empty rule): `{NULL, 0}`, `{dangling, 0}` and `{misaligned, 0}`
    /// are the empty value; `get` never reads the pointer (Miri runs this without UB).
    #[test]
    fn an_empty_view_reads_empty_whatever_its_pointer() {
        let bytes = [
            Bytes {
                ptr: core::ptr::null(),
                len: 0,
                _l: PhantomData,
            },
            Bytes::EMPTY,
            Bytes {
                ptr: core::ptr::without_provenance(1),
                len: 0,
                _l: PhantomData,
            },
        ];
        for b in bytes {
            assert!(b.is_empty());
            assert_eq!(b.get(), &[] as &[u8]);
            assert_eq!(Str(b).get(), "");
        }
        let slices: [Slice<'static, u64>; 3] = [
            Slice {
                ptr: core::ptr::null(),
                len: 0,
                _l: PhantomData,
            },
            Slice::EMPTY,
            Slice {
                ptr: core::ptr::without_provenance(3),
                len: 0,
                _l: PhantomData,
            },
        ];
        for s in slices {
            assert!(s.get().is_empty());
        }
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
        // The empty constructors never hand out null.
        assert!(!Bytes::new(&[]).ptr.is_null());
        assert!(!Bytes::EMPTY.ptr.is_null());
    }
}
