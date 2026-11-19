// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin header, `LinkedPlugin`, `plugin()` and the one exported macro, `export!` (IF §7.1, §7.7;
//! core 3.0, interface revision C.3).
//!
//! `unsafe` here: `export!`'s `#[unsafe(no_mangle)]`, the only `unsafe` token in
//! any busbar-ffi macro body (E4).

#![allow(unsafe_code)]

use crate::raw::{Shared, Str};
use crate::shim::{self, Image};
use crate::vt::{CancelFn, CloseFn, Entry, Kind, Table};

/// The stamp's size (IF §7.4).
pub const STAMP_SIZE: usize = 272;
/// The byte offset of `Stamp::kind` (IF §7.4), little-endian.
pub const STAMP_KIND_AT: usize = 24;
/// The most entries a kind table may hold: one method mask (interface revision D.2).
pub const ENTRIES_MAX: usize = 56;

/// The five header entries, in header order: describe, open, resume, cancel, close.
#[cfg(feature = "host")]
pub(crate) type Entries = (
    Option<Entry>,
    Option<Entry>,
    Option<Entry>,
    Option<CancelFn>,
    Option<CloseFn>,
);

mechanism! {
/// The stamp's bytes (IF §7.4: 272 bytes, align 8); busbar-plugin-abi's `Stamp` is the typed view.
#[repr(C, align(8))]
#[derive(Clone, Copy)]
pub struct StampBytes(pub [u8; 272]);

/// The only thing `busbar_plugin` returns. Identical for every kind. All pointers point into the image.
/// It begins with its own size in bytes (read by prefix: header fields are only ever appended) and the
/// number of entries its table holds (a method added later is one more entry; the host calls only the
/// entries an image has). Fields are private: a Rust image builds it only through `plugin()`, which ties
/// every entry and the table to one image type.
#[repr(C)]
pub struct Plugin {
    size: u32,
    entries: u32,
    stamp: Shared<StampBytes>,
    table: Shared<Option<Entry>>,
    describe: Option<Entry>,
    open: Option<Entry>,
    resume: Option<Entry>,
    cancel: Option<CancelFn>,
    close: Option<CloseFn>,
    former_names: Str<'static>,
}

pub const OPEN_DRY_RUN: u32 = 1;
/// The one exported symbol, emitted by `export!` only.
pub const SYMBOL: &[u8] = b"busbar_plugin\0";
}

/// The type of the one exported symbol, `busbar_plugin` (IF §7.1). UNSAFE-MIN r3.1: `export!` emits it as a
/// safe `extern "C" fn` (it only returns the address of a `'static` header), so the pointer type is safe too.
pub type EntryFn = extern "C" fn() -> *const Plugin;

/// Byte offsets of `Plugin`'s private fields, for busbar-plugin-abi's C-HEADER static asserts (IF §7.8).
pub const PLUGIN_SIZE_AT: usize = core::mem::offset_of!(Plugin, size);
/// Byte offset of `Plugin::entries`.
pub const PLUGIN_ENTRIES_AT: usize = core::mem::offset_of!(Plugin, entries);
/// Byte offset of `Plugin::stamp`.
pub const PLUGIN_STAMP_AT: usize = core::mem::offset_of!(Plugin, stamp);
/// Byte offset of `Plugin::table`.
pub const PLUGIN_TABLE_AT: usize = core::mem::offset_of!(Plugin, table);
/// Byte offset of `Plugin::describe`.
pub const PLUGIN_DESCRIBE_AT: usize = core::mem::offset_of!(Plugin, describe);
/// Byte offset of `Plugin::open`.
pub const PLUGIN_OPEN_AT: usize = core::mem::offset_of!(Plugin, open);
/// Byte offset of `Plugin::resume`.
pub const PLUGIN_RESUME_AT: usize = core::mem::offset_of!(Plugin, resume);
/// Byte offset of `Plugin::cancel`.
pub const PLUGIN_CANCEL_AT: usize = core::mem::offset_of!(Plugin, cancel);
/// Byte offset of `Plugin::close`.
pub const PLUGIN_CLOSE_AT: usize = core::mem::offset_of!(Plugin, close);
/// Byte offset of `Plugin::former_names`.
pub const PLUGIN_FORMER_NAMES_AT: usize = core::mem::offset_of!(Plugin, former_names);

// `Plugin` is `Sync` structurally: its two raw pointers are `Shared`, pointing at immutable statics of the
// image (`STAMP`, the kind table) that live as long as the image, which is never unloaded once admitted
// (I13); fn pointers are `Sync`; it has no interior mutability and no `&mut` API.

/// A compiled-in or exported plugin header built by `plugin()`. `Admitted::linked` takes only this, never
/// a bare `&'static Plugin` (A1).
#[repr(transparent)]
pub struct LinkedPlugin(Plugin);

impl LinkedPlugin {
    /// The header, as `busbar_plugin` returns it.
    pub const fn as_ptr(&self) -> *const Plugin {
        &self.0
    }
    /// The header of a `'static` image, for a caller that holds a `&'static Plugin` API (the SDK suites' frozen
    /// signatures, IF §14). Safe and additive: it only reads the field `as_ptr` already exposes.
    pub const fn plugin(&'static self) -> &'static Plugin {
        &self.0
    }
    #[cfg(any(test, feature = "host"))]
    pub(crate) const fn header(&self) -> &Plugin {
        &self.0
    }
}

/// `&LinkedPlugin` coerces to `&Plugin` (and `&'static` stays `&'static` for statics), so the SDK suites' frozen
/// `&'static Plugin` signatures (IF §14) take `plugin!`'s static directly. Safe: it only reads the field.
impl core::ops::Deref for LinkedPlugin {
    type Target = Plugin;
    fn deref(&self) -> &Plugin {
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

/// Build image `M`'s header for kind `K`: the header entries are `M`'s shims, the table is `M`'s `N`
/// entries, and the stamp must name `K` (a mismatch is a compile error in the `static`).
pub const fn plugin<M: Image, K: Kind, const N: usize>(
    table: &'static Table<M, N>,
    stamp: &'static StampBytes,
    former_names: Str<'static>,
) -> LinkedPlugin {
    assert!(
        stamp_kind(stamp) == K::CODE as u32,
        "the stamp names another kind"
    );
    assert!(N <= ENTRIES_MAX, "a kind table holds at most 56 entries");
    let describe: Entry = shim::describe::<M>;
    let open: Entry = shim::open::<M>;
    let resume: Entry = shim::resume::<M>;
    LinkedPlugin(Plugin {
        size: size_of::<Plugin>() as u32,
        entries: N as u32,
        stamp: Shared::new(core::ptr::from_ref(stamp)),
        table: Shared::new(table.as_ptr()),
        describe: Some(describe),
        open: Some(open),
        resume: Some(resume),
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
            ("table", self.table.get().is_null()),
            ("describe", self.describe.is_none()),
            ("open", self.open.is_none()),
            ("resume", self.resume.is_none()),
            ("cancel", self.cancel.is_none()),
            ("close", self.close.is_none()),
        ]
        .into_iter()
        .find_map(|(name, null)| null.then_some(name))
    }
    /// The header's size in bytes, as the image stated it (the host reads no field past it).
    pub const fn size(&self) -> u32 {
        self.size
    }
    /// The number of table entries the image stated.
    pub const fn entry_count(&self) -> u32 {
        self.entries
    }
    #[cfg(feature = "host")]
    pub(crate) fn stamp_ptr(&self) -> *const StampBytes {
        self.stamp.get()
    }
    #[cfg(feature = "host")]
    pub(crate) fn table_ptr(&self) -> *const Option<Entry> {
        self.table.get()
    }
    #[cfg(feature = "host")]
    pub(crate) fn entries(&self) -> Entries {
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
/// The plugin image emits this export exactly once and reserves the `busbar_plugin` symbol for this
/// signature. `$p` names its static header; the header, stamp and kind table remain live while the
/// image is mapped. The loader borrows them while opened and retains the mapping after admission.
///
/// ```text
/// busbar_ffi::export!(my_logic_crate::PLUGIN);
/// ```
#[macro_export]
macro_rules! export {
    ($p:path) => {
        const _: () = {
            // SAFETY: this is the image's reserved plugin entry symbol with the loader's exact C
            // signature. One export per image prevents symbol ambiguity; LinkedPlugin ties the
            // returned static header to its image's table and shims. The caller never frees it.
            #[unsafe(no_mangle)]
            pub extern "C" fn busbar_plugin() -> *const $crate::Plugin {
                $crate::LinkedPlugin::as_ptr(&$p)
            }
        };
    };
}

/// busbar-ffi instantiates `export!` once itself (UNSAFE-MIN §4.2), over a one-entry fixture image.
#[cfg(all(test, not(loom)))]
mod fixture {
    use super::*;
    use crate::raw::KindCode;
    use crate::raw::{Bytes, ChainBytes, Host, Out, Status, Token};
    use crate::shim::{ChainFut, Opening, Starts, Step};
    use crate::slots::{ChainBox, ChainRef, Slots};
    use crate::vt::{ChainArgs, kind};

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

    impl Starts<0> for Fixture {
        fn start<'i>(
            _p: &'i (),
            _h: &'static Host,
            args: ChainArgs<'_>,
        ) -> Option<(ChainFut<'i, ()>, ())> {
            let reference = args.blob(0)?;
            Some((
                Box::pin(async move {
                    let _ = reference.len();
                }),
                (),
            ))
        }
    }

    static TABLE: Table<Fixture, 1> = Table::new([shim::starts::<Fixture, 0>()]);
    static STAMP: StampBytes = {
        let mut bytes = [0u8; STAMP_SIZE];
        bytes[STAMP_KIND_AT] = KindCode::Secret as u8;
        StampBytes(bytes)
    };
    pub static PLUGIN: LinkedPlugin =
        plugin::<Fixture, kind::Secret, 1>(&TABLE, &STAMP, Str::EMPTY);

    crate::export!(PLUGIN);

    #[test]
    fn the_fixture_header_has_every_entry() {
        assert_eq!(PLUGIN.header().null_field(), None);
        assert!(KindCode::from_raw(stamp_kind(&STAMP)).is_some());
        assert_eq!(stamp_kind(&STAMP), KindCode::Secret as u32);
        assert_eq!(PLUGIN.header().entry_count(), 1);
        assert_eq!(PLUGIN.header().size() as usize, size_of::<Plugin>());
    }
}
