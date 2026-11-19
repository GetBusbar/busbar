// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one call record, the one entry type and the one table type (core contract 3.0, interface revision C.3).
//!
//! Every method of every kind crosses the boundary in the same shape: `Entry(inst, host, &Call, &mut RawOut)`.
//! A kind's table is an array of `Entry`; the header says how many it holds. This crate knows no kind: it
//! does not know what a method's `head`, `texts` or `blobs` mean, only how to lend them. A kind states the
//! layout of each of its methods (busbar-plugin-abi's `kind!`), and a field added later goes at the end of
//! `head`, `texts` or `blobs`, where an older image never looks.
//!
//! `unsafe` here: the three entry fn-pointer aliases (`Entry`, `CancelFn`, `CloseFn`) and the one read of a
//! pair-list blob (`Args::pairs`).
//!
//! # Entry safety contract
//!
//! The function-pointer types cannot express the relationship between an opaque instance address, its
//! image's table and a live host handle. Before calling an entry, the host must establish:
//!
//! - The function belongs to the same admitted image as `inst`; a non-null `inst` is the still-live,
//!   correctly aligned allocation returned by that image's `Inst::into_instance`. The image stays mapped
//!   throughout the call. Null is allowed only for the header entries `describe`, `open` and `resume`
//!   (an open chain), and for `cancel` and `close`.
//! - `call` and `out` satisfy their raw-view contracts for the entire call, and `call` follows the layout
//!   the kind states for the method in that table position: every text is UTF-8, and every blob the layout
//!   names a pair list is the borrowed array of `Pair` itself (`Bytes::of_pairs`).
//! - For an async start or a resume, every blob stays immutable and allocated until the chain retires;
//!   `ChainBufs` owns that storage, and `Chain::drop` cancels before its buffers are freed.
//! - A session or chain token (`Call::session`) has one active caller (I6), including cancellation and
//!   the consuming end. The host's `Session` and `Chain` require exclusive borrows and are the only code
//!   that puts a live token in a call; closing the instance cannot overlap any call.
//!
//! `host::invoke`, `cancel_raw` and `Instance::drop` are the call sites; `shim` implements the callee side.

#![allow(unsafe_code)]

use core::ffi::c_void;
use core::marker::PhantomData;

use crate::raw::{
    Bytes, ChainBytes, ChainId, Host, KindCode, Pair, RawOut, Slice, Status, Str, Token,
};

mechanism! {
/// The one call record. Passed by address, so a field appended later is never read by an older image.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Call<'a> {
    session: u64,
    mono_ns: u64,
    head: Bytes<'a>,
    texts: Slice<'a, Str<'a>>,
    blobs: Slice<'a, Bytes<'a>>,
}

/// The only entry type. Every table is an array of these; `describe`, `open` and `resume` are of it too.
// SAFETY: uphold this module's entry safety contract.
pub type Entry = for<'a> unsafe extern "C" fn(*const c_void, &'static Host, &'a Call<'a>, &'a mut RawOut) -> Status;
/// Drop a chain (bit 63 clear) or a session (bit 63 set); `inst` null = the open slab. Idempotent.
// SAFETY: uphold this module's entry safety contract. Exclude concurrent calls for this token, even
// when cancelling repeatedly; idempotence permits sequential stale calls, not concurrent live removal.
// Keep chain buffers alive until this call returns. Null selects this image's open slab.
pub type CancelFn = unsafe extern "C" fn(*const c_void, Token) -> Status;
/// Drop the instance with its chains and sessions, the plugin value last.
// SAFETY: null is a no-op. Otherwise transfer the live allocation from this image's INSTANCE answer
// exactly once, after all entries and handle borrows have ended. Nothing may access it after this call.
// Keep the image mapped through all field destructors and the allocation's release (`drop_inst`).
pub type CloseFn = unsafe extern "C" fn(*const c_void) -> Status;
}

/// Byte offset of `Call::session` (a private field), for the C header's static asserts.
pub const CALL_SESSION_AT: usize = core::mem::offset_of!(Call<'static>, session);
/// Byte offset of `Call::mono_ns`.
pub const CALL_MONO_NS_AT: usize = core::mem::offset_of!(Call<'static>, mono_ns);
/// Byte offset of `Call::head`.
pub const CALL_HEAD_AT: usize = core::mem::offset_of!(Call<'static>, head);
/// Byte offset of `Call::texts`.
pub const CALL_TEXTS_AT: usize = core::mem::offset_of!(Call<'static>, texts);
/// Byte offset of `Call::blobs`.
pub const CALL_BLOBS_AT: usize = core::mem::offset_of!(Call<'static>, blobs);
const _: () = assert!(
    size_of::<Call<'static>>() == 64,
    "the call record is 64 bytes"
);

impl<'a> Call<'a> {
    /// A call with no fields: `describe`, and any method that takes none.
    pub const EMPTY: Call<'static> = Call {
        session: 0,
        mono_ns: 0,
        head: Bytes::EMPTY,
        texts: Slice::EMPTY,
        blobs: Slice::EMPTY,
    };
    /// A plain call (session 0). `mono_ns` is the host's one clock reading for the operation (0: none).
    /// The session of a call is never chosen by the caller: the host's `Session` and `Chain` set it.
    pub const fn new(
        mono_ns: u64,
        head: &'a [u8],
        texts: &'a [Str<'a>],
        blobs: &'a [Bytes<'a>],
    ) -> Self {
        Call {
            session: 0,
            mono_ns,
            head: Bytes::new(head),
            texts: Slice::new(texts),
            blobs: Slice::new(blobs),
        }
    }
    /// The same call on session or chain `token` (the host handles only).
    #[cfg(feature = "host")]
    pub(crate) const fn on(&self, token: Token) -> Call<'a> {
        Call {
            session: token,
            mono_ns: self.mono_ns,
            head: self.head,
            texts: self.texts,
            blobs: self.blobs,
        }
    }
    /// The same call at another clock reading.
    pub const fn at(&self, mono_ns: u64) -> Call<'a> {
        Call {
            session: self.session,
            mono_ns,
            head: self.head,
            texts: self.texts,
            blobs: self.blobs,
        }
    }
    /// The session or chain token; 0 for a plain call.
    pub const fn session(&self) -> u64 {
        self.session
    }
    /// The host's one clock reading for this operation (monotonic nanoseconds; 0 = not given).
    pub const fn mono_ns(&self) -> u64 {
        self.mono_ns
    }
    /// The method's numbers: one plain record, read by prefix.
    pub fn head(&self) -> &'a [u8] {
        self.head.get()
    }
    /// The borrowed UTF-8 fields, by position.
    pub fn texts(&self) -> &'a [Str<'a>] {
        self.texts.get()
    }
    /// The borrowed byte fields, by position.
    pub fn blobs(&self) -> &'a [Bytes<'a>] {
        self.blobs.get()
    }
}

/// What a kind's sync adapter reads a call through. Minted only by this crate's shims, inside an entry:
/// that the call follows the method's layout is the entry caller's obligation (the module contract), which
/// is what makes `pairs` a safe read.
#[derive(Clone, Copy)]
pub struct Args<'a> {
    call: &'a Call<'a>,
}

impl<'a> Args<'a> {
    pub(crate) const fn new(call: &'a Call<'a>) -> Self {
        Args { call }
    }
    pub const fn mono_ns(&self) -> u64 {
        self.call.mono_ns
    }
    pub fn head(&self) -> &'a [u8] {
        self.call.head()
    }
    /// Text `at`, or None when the caller sent fewer.
    pub fn text(&self, at: usize) -> Option<Str<'a>> {
        self.call.texts().get(at).copied()
    }
    /// Blob `at`, or None when the caller sent fewer.
    pub fn blob(&self, at: usize) -> Option<Bytes<'a>> {
        self.call.blobs().get(at).copied()
    }
    /// The blobs from `at` on (a method's trailing list of byte fields); empty when there are none.
    pub fn blobs_from(&self, at: usize) -> Slice<'a, Bytes<'a>> {
        Slice::new(self.call.blobs().get(at..).unwrap_or(&[]))
    }
    /// Blob `at` as the pair list its layout says it is. None: missing, or not a whole, aligned array.
    pub fn pairs(&self, at: usize) -> Option<Slice<'a, Pair<'a>>> {
        let blob = self.blob(at)?;
        // SAFETY: an `Args` exists only inside an entry, whose caller guarantees the call follows the
        // method's layout (the module contract): a blob the layout names a pair list was built by
        // `Bytes::of_pairs` from a `&'a [Pair<'a>]`. `as_pairs` checks length and alignment itself.
        unsafe { blob.as_pairs() }
    }
}

/// What a kind's async adapter reads a call through: numbers now, bytes as chain-scoped handles. Texts
/// are not offered: nothing borrowed from the call may outlive it.
pub struct ChainArgs<'a> {
    call: &'a Call<'a>,
    id: &'a ChainId,
}

impl<'a> ChainArgs<'a> {
    pub(crate) const fn new(call: &'a Call<'a>, id: &'a ChainId) -> Self {
        ChainArgs { call, id }
    }
    pub const fn mono_ns(&self) -> u64 {
        self.call.mono_ns
    }
    pub fn head(&self) -> &'a [u8] {
        self.call.head()
    }
    /// Blob `at` as the chain keeps it, or None when the caller sent fewer.
    pub fn blob(&self, at: usize) -> Option<ChainBytes> {
        let blob = *self.call.blobs().get(at)?;
        Some(ChainBytes::of(blob, self.id))
    }
}

/// One table position, built only by `shim`'s five constructors for image `M`. Nullable in C (a null is
/// refused at admit). Not `Copy` or `Clone`: an entry cannot be lifted out of its table.
#[repr(transparent)]
pub struct Slot<M>(Option<Entry>, PhantomData<fn() -> M>);

impl<M> Slot<M> {
    pub(crate) const fn new(entry: Entry) -> Self {
        Slot(Some(entry), PhantomData)
    }
}

/// A kind table built for image `M`: `N` entries, every one `M`'s shim, in the kind's declaration order.
#[repr(transparent)]
pub struct Table<M, const N: usize>([Slot<M>; N]);

impl<M, const N: usize> Table<M, N> {
    pub const fn new(slots: [Slot<M>; N]) -> Self {
        Table(slots)
    }
    /// The first entry's address, for the header's `table`.
    pub(crate) const fn as_ptr(&self) -> *const Option<Entry> {
        self.0.as_ptr().cast()
    }
    /// How many entries the table holds (the header's `entries`).
    pub const fn len(&self) -> usize {
        N
    }
    pub const fn is_empty(&self) -> bool {
        N == 0
    }
}

mod sealed {
    pub trait Kind {}
}

/// One of the kind codes. Sealed: this crate implements it for `kind::*` only. It carries the code a
/// stamp must name and nothing else: the table of every kind has the one layout.
pub trait Kind: sealed::Kind + 'static {
    const CODE: KindCode;
}

/// The kind markers: the list of kind codes, and the only place this crate names a kind.
pub mod kind {
    use super::{Kind, KindCode, sealed};

    macro_rules! markers {
        ($($K:ident)*) => {$(
            pub struct $K;
            impl sealed::Kind for $K {}
            impl Kind for $K {
                const CODE: KindCode = KindCode::$K;
            }
        )*};
    }
    markers!(Store Secret Auth Hook Export Plane Transport);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_call_lends_what_it_was_built_from() {
        let head = 7u32.to_le_bytes();
        let texts = [Str::new("a"), Str::new("b")];
        let pairs = [Pair {
            name: Str::new("accept"),
            value: Bytes::new(b"*/*"),
        }];
        let blobs = [Bytes::new(b"body"), Bytes::of_pairs(&pairs)];
        let call = Call::new(9, &head, &texts, &blobs);
        assert_eq!((call.session(), call.mono_ns()), (0, 9));
        let args = Args::new(&call);
        assert_eq!(args.head(), &head);
        assert_eq!(args.text(1).map(Str::get), Some("b"));
        assert!(args.text(2).is_none());
        assert_eq!(args.blob(0).map(Bytes::get), Some(&b"body"[..]));
        let read = args.pairs(1).map(Slice::get).unwrap_or(&[]);
        assert_eq!(read.len(), 1);
        assert_eq!(read[0].name.get(), "accept");
        assert_eq!(read[0].value.get(), b"*/*");
        assert_eq!(args.blobs_from(1).len(), 1);
        assert!(args.blobs_from(5).is_empty());
        assert!(Call::EMPTY.head().is_empty());
    }
}
