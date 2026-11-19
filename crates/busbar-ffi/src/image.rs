// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The loader's door to an image (feature `host`; IF §11.1 steps 8-9, UNSAFE-MIN §2.2, §2.5).
//!
//! `Opened::open` dlopens the staged image, calls `busbar_plugin` and bounds-checks the header, the stamp,
//! the entry table and `former_names` against the image's own segments (H4: `object` over the bytes the
//! loader already holds; base = `busbar_plugin`'s address minus its symbol value). Every view before
//! admission borrows `&Opened`, and nothing `'static` exists until `Opened::admit` leaks the library
//! (exit a); `Opened::close` drops it, on the loader's ffi worker (exit b).
//!
//! `unsafe` here: `Library::new`, `Library::get`, the header view (opened and admitted), the stamp view
//! and the entry table view.

#![allow(unsafe_code)]

use std::ffi::OsStr;

use object::{Object, ObjectSegment};

use crate::header::{EntryFn, LinkedPlugin, Plugin, STAMP_SIZE, SYMBOL, StampBytes, stamp_kind};
use crate::raw::{Bytes, KindCode, Shared};
use crate::vt::{Entry, Kind};

/// Why an image was not opened or admitted (the loader maps each to its `Refusal`).
#[derive(Debug)]
pub enum ImageError {
    /// dlopen failed.
    Load(libloading::Error),
    /// No `busbar_plugin` symbol (in the loaded image or in its bytes).
    NoSymbol,
    /// The bytes are not an image `object` can read.
    Parse,
    /// A header part lies outside the image's segments or is misaligned (H4 `ImageBounds`), named.
    Bounds(&'static str),
    /// The stamp names no kind.
    Kind,
    /// A null header or table entry (step 9, `DoorStampMismatch`), named.
    Null(&'static str),
    /// The header states a size smaller than this host reads, or more table entries than a kind may have.
    Header(&'static str),
}

/// The size in bytes of a table of `entries` entries. None: more than a kind may have.
fn table_size(entries: u32) -> Option<usize> {
    let entries = usize::try_from(entries).ok()?;
    (entries <= crate::header::ENTRIES_MAX).then(|| entries * size_of::<Option<Entry>>())
}

/// The image's mapped segments, at run time.
struct Segments(Vec<(usize, usize)>);

impl Segments {
    fn of(bytes: &[u8], entry: usize) -> Result<Segments, ImageError> {
        let file = object::File::parse(bytes).map_err(|_| ImageError::Parse)?;
        let exports = file.exports().map_err(|_| ImageError::Parse)?;
        let symbol = exports
            .iter()
            .find(|e| matches!(e.name(), b"busbar_plugin" | b"_busbar_plugin"))
            .ok_or(ImageError::NoSymbol)?;
        let base = entry.wrapping_sub(symbol.address() as usize);
        Ok(Segments(
            file.segments()
                .map(|segment| {
                    let start = base.wrapping_add(segment.address() as usize);
                    (start, start.saturating_add(segment.size() as usize))
                })
                .collect(),
        ))
    }
    /// `[addr, addr + len)` lies inside one segment and `addr` is `align`-aligned.
    fn check(
        &self,
        what: &'static str,
        addr: usize,
        len: usize,
        align: usize,
    ) -> Result<(), ImageError> {
        let Some(end) = addr.checked_add(len) else {
            return Err(ImageError::Bounds(what));
        };
        let inside = self
            .0
            .iter()
            .any(|&(start, stop)| addr >= start && end <= stop);
        if inside && addr.is_multiple_of(align) {
            Ok(())
        } else {
            Err(ImageError::Bounds(what))
        }
    }
}

/// The stamp a checked header names.
fn stamp_of(header: &Plugin) -> &StampBytes {
    // SAFETY: every `Plugin` reached here is a checked one: an `Opened` header whose stamp pointer `open`
    // bounds-checked (272 bytes, aligned, inside the mapped image, which stays mapped while the header is
    // borrowed), or a `LinkedPlugin` built by `plugin()` from a `&'static StampBytes`. Stamps are immutable.
    unsafe { &*header.stamp_ptr() }
}

/// A dlopened image, header checked, not admitted.
pub struct Opened {
    lib: libloading::Library,
    /// The header `busbar_plugin` returned, kept as that pointer (its provenance intact) for the views.
    plugin: Shared<Plugin>,
}

impl Opened {
    /// dlopen `path` (the staged image whose verified bytes are `bytes`), call `busbar_plugin` and
    /// bounds-check every header part (admit step 9). Runs the image's initializers: call it on the
    /// loader's ffi worker.
    pub fn open(path: &OsStr, bytes: &[u8]) -> Result<Opened, ImageError> {
        // SAFETY: loading runs the image's initializers. The loader calls this only for an image whose
        // signature, stamp and manifest it verified (admit steps 1-7), on its permanent ffi worker, and
        // native plugins are trusted code (UNSAFE-MIN §2.1 trust note).
        let lib = unsafe { libloading::Library::new(path) }.map_err(ImageError::Load)?;
        // SAFETY: `busbar_plugin` is emitted only by `export!`, with exactly this signature.
        let symbol = unsafe { lib.get::<EntryFn>(SYMBOL) };
        let entry = match symbol {
            Ok(symbol) => *symbol,
            Err(_) => return Err(ImageError::NoSymbol),
        };
        let segments = Segments::of(bytes, entry as usize)?;
        let plugin = entry();
        segments.check(
            "header",
            plugin.addr(),
            size_of::<Plugin>(),
            align_of::<Plugin>(),
        )?;
        let opened = Opened {
            lib,
            plugin: Shared::new(plugin),
        };
        let header = opened.header();
        segments.check(
            "stamp",
            header.stamp_ptr().addr(),
            STAMP_SIZE,
            align_of::<StampBytes>(),
        )?;
        if (header.size() as usize) < size_of::<Plugin>() {
            return Err(ImageError::Header("size"));
        }
        KindCode::from_raw(stamp_kind(stamp_of(header))).ok_or(ImageError::Kind)?;
        let table = table_size(header.entry_count()).ok_or(ImageError::Header("entries"))?;
        segments.check(
            "table",
            header.table_ptr().addr(),
            table,
            align_of::<usize>(),
        )?;
        let (names, len) = header.former_names_raw().bytes().span();
        if len > 0 {
            segments.check("former_names", names, len, 1)?;
        }
        Ok(opened)
    }

    /// The header (bounds-checked by `open`), borrowed from `self`.
    pub fn header(&self) -> &Plugin {
        let p = self.plugin.get();
        // SAFETY: `p` is the pointer `busbar_plugin` returned. `open` checked that the header lies, aligned,
        // inside the image's mapped segments; the image stays mapped while `self` holds the library, and
        // the view borrows `self`. The header is immutable.
        unsafe { &*p }
    }

    /// The stamp bytes (bounds-checked), borrowed from `self`.
    pub fn stamp(&self) -> &StampBytes {
        stamp_of(self.header())
    }

    /// `former_names` as checked UTF-8, borrowed from `self`.
    pub fn former_names(&self) -> Result<&str, core::str::Utf8Error> {
        let names: Bytes<'_> = self.header().former_names_raw().bytes();
        core::str::from_utf8(names.get())
    }

    /// The first null header or table entry, named, without admitting the image (DES-443 r3: inspect checks it
    /// on the opened image, then closes it). The same check `admit` runs; nothing it reads outlives the call.
    pub fn null_field(&self) -> Option<&'static str> {
        Admitted {
            plugin: self.plugin,
        }
        .null_field()
    }

    /// Exit a: the image is admitted and never unloaded (I13). A null header or table entry refuses it
    /// and hands the image back for `close`.
    pub fn admit(self) -> Result<Admitted, (Opened, ImageError)> {
        let admitted = Admitted {
            plugin: self.plugin,
        };
        if let Some(field) = admitted.null_field() {
            return Err((self, ImageError::Null(field)));
        }
        core::mem::forget(self.lib);
        Ok(admitted)
    }

    /// Exit b: unload a refused image. Call it on the loader's ffi worker.
    pub fn close(self) {
        drop(self.lib);
    }
}

/// An admitted image: a compiled-in `LinkedPlugin`, or a dropped-in image whose library is never
/// unloaded. `Copy`: it is only a pointer to an immutable, `'static` header (`Send` and `Sync` through
/// `Shared`, as `Plugin` is `Sync`).
#[derive(Clone, Copy)]
pub struct Admitted {
    plugin: Shared<Plugin>,
}

impl core::fmt::Debug for Admitted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Admitted")
            .field("plugin", &self.plugin.get())
            .finish()
    }
}

impl Admitted {
    /// A compiled-in plugin (replaces r34's `admit_linked(&'static Plugin)`).
    pub fn linked(plugin: &'static LinkedPlugin) -> Result<Admitted, ImageError> {
        let admitted = Admitted {
            plugin: Shared::new(core::ptr::from_ref(plugin.header())),
        };
        match admitted.null_field() {
            Some(field) => Err(ImageError::Null(field)),
            None => Ok(admitted),
        }
    }

    /// A compiled-in header held as the `&'static Plugin` the SDK suites' frozen signatures take (IF §14).
    /// Safe: `Plugin`'s fields are private, so a `'static` one is a `LinkedPlugin`'s (`plugin()`). It runs the
    /// null check `linked` runs, and the loader's admission still scans the stamp (A1).
    pub fn from_header(plugin: &'static Plugin) -> Result<Admitted, ImageError> {
        let admitted = Admitted {
            plugin: Shared::new(core::ptr::from_ref(plugin)),
        };
        match admitted.null_field() {
            Some(field) => Err(ImageError::Null(field)),
            None => Ok(admitted),
        }
    }

    /// The header.
    pub fn header(&self) -> &'static Plugin {
        let p = self.plugin.get();
        // SAFETY: `p` is derived from a `&'static LinkedPlugin` / `&'static Plugin`, or is the bounds-checked
        // header `busbar_plugin` returned for an image whose library `admit` leaked, so it is never unmapped
        // (I13); the header is immutable.
        unsafe { &*p }
    }

    /// `former_names` as checked UTF-8 (`add` and the admit path compared it with the signed manifest already);
    /// empty when the header states bytes that are not UTF-8.
    pub fn former_names(&self) -> &'static str {
        let names: Bytes<'static> = self.header().former_names_raw().bytes();
        core::str::from_utf8(names.get()).unwrap_or("")
    }

    /// The stamp bytes.
    pub fn stamp(&self) -> &'static StampBytes {
        stamp_of(self.header())
    }

    /// The kind the stamp names.
    pub fn kind(&self) -> Option<KindCode> {
        KindCode::from_raw(stamp_kind(self.stamp()))
    }

    /// Whether the stamp names kind `K`.
    pub(crate) fn is<K: Kind>(&self) -> bool {
        stamp_kind(self.stamp()) == K::CODE as u32
    }

    /// The number of entries in the image's kind table.
    pub fn entries(&self) -> usize {
        self.table().len()
    }

    /// The kind table: `entries` entries, each nullable.
    pub(crate) fn table(&self) -> &'static [Option<Entry>] {
        let header = self.header();
        let p = header.table_ptr();
        let Some(len) = usize::try_from(header.entry_count())
            .ok()
            .filter(|len| *len <= crate::header::ENTRIES_MAX && !p.is_null())
        else {
            return &[];
        };
        // SAFETY: the table is an array of `entries` nullable `Entry` pointers, the one table layout of
        // every kind: a `LinkedPlugin`'s by `plugin()` (a `&'static Table<M, N>` with `entries == N`), a
        // dropped-in image's by its build, and `open` checked it lies, aligned and at that size, inside
        // the never-unloaded image. It is immutable.
        unsafe { core::slice::from_raw_parts(p, len) }
    }

    /// Entry `slot` of the kind table. None: the image has fewer entries, or that entry is null.
    pub(crate) fn entry(&self, slot: usize) -> Option<Entry> {
        self.table().get(slot).copied().flatten()
    }

    /// The first null header or table entry, named.
    pub fn null_field(&self) -> Option<&'static str> {
        if let Some(field) = self.header().null_field() {
            return Some(field);
        }
        if (self.header().size() as usize) < size_of::<Plugin>() {
            return Some("size");
        }
        // The entries have no names here (this crate knows no kind): the kind's contract names the
        // position (`<kind>::METHODS[slot]`) when the loader reports it.
        self.table()
            .iter()
            .any(Option::is_none)
            .then_some("table entry")
    }
}
