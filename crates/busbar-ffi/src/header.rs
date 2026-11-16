// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin header, `LinkedPlugin`, `plugin()` and the one exported macro, `export!` (IF §7.1, §7.7;
//! UNSAFE-MIN §2.2 A1, §4.2).
//!
//! `unsafe` here: `export!`'s `#[unsafe(no_mangle)]`, the only `unsafe` token in
//! any busbar-ffi macro body (E4).

#![allow(unsafe_code)]

use core::ffi::c_void;

use crate::raw::{Shared, Str};
use crate::shim::{self, Image};
use crate::vt::{Built, CancelFn, CloseFn, DescribeFn, Kind, OpenFn, ResumeFn};

/// The stamp's size (IF §7.4).
pub const STAMP_SIZE: usize = 272;
/// The byte offset of `Stamp::kind` (IF §7.4), little-endian.
pub const STAMP_KIND_AT: usize = 24;

mechanism! {
/// The stamp's bytes (IF §7.4: 272 bytes, align 8); busbar-plugin-abi's `Stamp` is the typed view.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct StampBytes(pub [u8; 272]);

/// The only thing `busbar_plugin` returns. Identical for every kind. All pointers point into the image.
/// Fields are private: a Rust image builds it only through `plugin()`, which ties every entry and the
/// table to one image type.
#[repr(C)]
pub struct Plugin {
    stamp: Shared<StampBytes>,
    kind_vt: Shared<c_void>,
    describe: Option<DescribeFn>,
    open: Option<OpenFn>,
    resume: Option<ResumeFn>,
    cancel: Option<CancelFn>,
    close: Option<CloseFn>,
    former_names: Str<'static>,
}

pub const OPEN_DRY_RUN: u32 = 1;
/// The one exported symbol, emitted by `export!` only.
pub const SYMBOL: &[u8] = b"busbar_plugin\0";
}

/// Byte offsets of `Plugin`'s private fields, for busbar-plugin-abi's C-HEADER static asserts (IF §7.8).
pub const PLUGIN_STAMP_AT: usize = core::mem::offset_of!(Plugin, stamp);
/// Byte offset of `Plugin::kind_vt`.
pub const PLUGIN_KIND_VT_AT: usize = core::mem::offset_of!(Plugin, kind_vt);

// `Plugin` is `Sync` structurally: its two raw pointers are `Shared`, pointing at immutable statics of the
// image (`STAMP`, the kind table) that live as long as the image, which is never unloaded once admitted
// (I13); it has no interior mutability and no `&mut` API.

/// A compiled-in or exported plugin header built by `plugin()`. `Admitted::linked` takes only this, never
/// a bare `&'static Plugin` (A1).
#[repr(transparent)]
pub struct LinkedPlugin(Plugin);

impl LinkedPlugin {
    /// The header, as `busbar_plugin` returns it.
    pub const fn as_ptr(&self) -> *const Plugin {
        &self.0
    }
    #[cfg(any(test, feature = "host"))]
    pub(crate) const fn header(&self) -> &Plugin {
        &self.0
    }
}

/// The kind a stamp names.
pub(crate) const fn stamp_kind(stamp: &StampBytes) -> u32 {
    let b = &stamp.0;
    u32::from_le_bytes([
        b[STAMP_KIND_AT],
        b[STAMP_KIND_AT + 1],
        b[STAMP_KIND_AT + 2],
        b[STAMP_KIND_AT + 3],
    ])
}

/// Build image `M`'s header for kind `K`: the header entries are `M`'s shims, the table is `M`'s, and the
/// stamp must name `K` (a mismatch is a compile error in the `static`).
pub const fn plugin<M: Image, K: Kind>(
    vt: &'static Built<M, K::Vt>,
    stamp: &'static StampBytes,
    former_names: Str<'static>,
) -> LinkedPlugin {
    assert!(
        stamp_kind(stamp) == K::CODE as u32,
        "the stamp names another kind"
    );
    LinkedPlugin(Plugin {
        stamp: Shared::new(core::ptr::from_ref(stamp)),
        kind_vt: Shared::new(vt.as_ptr()),
        describe: Some(shim::describe::<M>),
        open: Some(shim::open::<M>),
        resume: Some(shim::resume::<M>),
        cancel: Some(shim::cancel::<M>),
        close: Some(shim::close::<M>),
        former_names,
    })
}

impl Plugin {
    /// The first null header entry, named (admit refuses it, step 9).
    pub fn null_field(&self) -> Option<&'static str> {
        [
            ("stamp", self.stamp.get().is_null()),
            ("kind_vt", self.kind_vt.get().is_null()),
            ("describe", self.describe.is_none()),
            ("open", self.open.is_none()),
            ("resume", self.resume.is_none()),
            ("cancel", self.cancel.is_none()),
            ("close", self.close.is_none()),
        ]
        .into_iter()
        .find_map(|(name, null)| null.then_some(name))
    }
    #[cfg(feature = "host")]
    pub(crate) fn stamp_ptr(&self) -> *const StampBytes {
        self.stamp.get()
    }
    #[cfg(feature = "host")]
    pub(crate) fn kind_vt_ptr(&self) -> *const c_void {
        self.kind_vt.get()
    }
    #[cfg(feature = "host")]
    pub(crate) fn entries(
        &self,
    ) -> (
        Option<DescribeFn>,
        Option<OpenFn>,
        Option<ResumeFn>,
        Option<CancelFn>,
        Option<CloseFn>,
    ) {
        (
            self.describe,
            self.open,
            self.resume,
            self.cancel,
            self.close,
        )
    }
    #[cfg(feature = "host")]
    pub(crate) fn former_names_raw(&self) -> Str<'static> {
        self.former_names
    }
}

/// Emits the one exported symbol of a dropped-in plugin: `busbar_plugin`, returning `$p`'s header.
/// `$p` must be a `LinkedPlugin` (`busbar_ffi::plugin(..)`); `$p` and `$crate` sit only in the safe body.
///
/// ```text
/// busbar_ffi::export!(my_logic_crate::PLUGIN);
/// ```
#[macro_export]
macro_rules! export {
    ($p:path) => {
        const _: () = {
            #[unsafe(no_mangle)]
            pub extern "C" fn busbar_plugin() -> *const $crate::Plugin {
                $crate::LinkedPlugin::as_ptr(&$p)
            }
        };
    };
}

/// busbar-ffi instantiates `export!` once itself (UNSAFE-MIN §4.2), over a secret-kind fixture image.
#[cfg(all(test, not(loom)))]
mod fixture {
    use super::*;
    use crate::raw::KindCode;
    use crate::raw::{Bytes, ChainBytes, Host, Out, Status, Token};
    use crate::shim::{ChainFut, Opening, Start1, Step};
    use crate::slots::{ChainBox, ChainRef, Slots};
    use crate::vt::{kind, secret};

    pub struct Fixture;
    static GLOBAL: Slots<ChainBox<(), ()>> = Slots::new();

    impl Image for Fixture {
        type Plugin = ();
        type Session = ();
        type Reply = ();
        type Inbox = ();
        fn global() -> &'static Slots<ChainBox<(), ()>> {
            &GLOBAL
        }
        fn describe(_h: &'static Host, _out: &mut Out<'_>) -> Status {
            Status::OK
        }
        fn open(
            _h: &'static Host,
            _config: Bytes<'_>,
            _chained: ChainBytes,
            _flags: u32,
            _out: &mut Out<'_>,
        ) -> Opening<(), ()> {
            Opening::Done(Status::OK)
        }
        fn poll(
            mut chain: ChainRef<'_, (), ()>,
            _results: Option<ChainBytes>,
            _out: &mut Out<'_>,
        ) -> Step {
            match chain.poll() {
                core::task::Poll::Ready(()) => Step::Ready(Status::OK),
                core::task::Poll::Pending => Step::Fault,
            }
        }
        fn parked(_token: Token, _out: &mut Out<'_>) -> Status {
            Status::NEED
        }
        fn opened(_token: Token, _out: &mut Out<'_>) -> Status {
            Status::OK
        }
    }

    impl Start1<Bytes<'static>, 0> for Fixture {
        fn start<'i>(
            _p: &'i (),
            _h: &'static Host,
            reference: ChainBytes,
        ) -> (ChainFut<'i, ()>, ()) {
            (
                Box::pin(async move {
                    let _ = reference.len();
                }),
                (),
            )
        }
    }

    static VT: Built<Fixture, secret::Vt> = secret::Vt::build::<Fixture>();
    static STAMP: StampBytes = {
        let mut bytes = [0u8; STAMP_SIZE];
        bytes[STAMP_KIND_AT] = KindCode::Secret as u8;
        StampBytes(bytes)
    };
    pub static PLUGIN: LinkedPlugin = plugin::<Fixture, kind::Secret>(&VT, &STAMP, Str::EMPTY);

    crate::export!(PLUGIN);

    #[test]
    fn the_fixture_header_has_every_entry() {
        assert_eq!(PLUGIN.header().null_field(), None);
        assert!(KindCode::from_raw(stamp_kind(&STAMP)).is_some());
        assert_eq!(stamp_kind(&STAMP), KindCode::Secret as u32);
    }
}
