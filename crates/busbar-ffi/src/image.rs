// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The loader's door to an image (feature `host`; IF §11.1 steps 8-9, UNSAFE-MIN §2.2, §2.5).
//!
//! `Opened::open` dlopens the staged image, calls `busbar_plugin` and bounds-checks the header, the stamp,
//! the kind table and `former_names` against the image's own segments (H4: `object` over the bytes the
//! loader already holds; base = `busbar_plugin`'s address minus its symbol value). Every view before
//! admission borrows `&Opened`, and nothing `'static` exists until `Opened::admit` leaks the library
//! (exit a); `Opened::close` drops it, on the loader's ffi worker (exit b).
//!
//! `unsafe` here: `Library::new`, `Library::get`, the header view (opened and admitted), the stamp view
//! and the `vt::<K>` cast.

#![allow(unsafe_code)]

use std::ffi::OsStr;

use object::{Object, ObjectSegment};

use crate::header::{LinkedPlugin, Plugin, STAMP_SIZE, SYMBOL, StampBytes, stamp_kind};
use crate::raw::{Bytes, KindCode};
use crate::vt::{Kind, auth, export, hook, kind, plane, secret, store, transport};

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
}

/// The size of kind `code`'s table.
fn vt_size(code: KindCode) -> usize {
    match code {
        KindCode::Store => size_of::<store::Vt>(),
        KindCode::Secret => size_of::<secret::Vt>(),
        KindCode::Auth => size_of::<auth::Vt>(),
        KindCode::Hook => size_of::<hook::Vt>(),
        KindCode::Export => size_of::<export::Vt>(),
        KindCode::Plane => size_of::<plane::Vt>(),
        KindCode::Transport => size_of::<transport::Vt>(),
    }
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
    /// The header's address (provenance exposed).
    plugin: usize,
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
        let symbol = unsafe { lib.get::<extern "C" fn() -> *const Plugin>(SYMBOL) };
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
            plugin: plugin.expose_provenance(),
        };
        let header = opened.header();
        segments.check(
            "stamp",
            header.stamp_ptr().addr(),
            STAMP_SIZE,
            align_of::<StampBytes>(),
        )?;
        let code = KindCode::from_raw(stamp_kind(stamp_of(header))).ok_or(ImageError::Kind)?;
        segments.check(
            "kind_vt",
            header.kind_vt_ptr().addr(),
            vt_size(code),
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
        let p = core::ptr::with_exposed_provenance::<Plugin>(self.plugin);
        // SAFETY: `open` checked that the header lies, aligned, inside the image's mapped segments; the
        // image stays mapped while `self` holds the library, and the view borrows `self`.
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
/// unloaded. `Copy`: it is only an address of an immutable, `'static` header.
#[derive(Clone, Copy, Debug)]
pub struct Admitted {
    plugin: usize,
}

impl Admitted {
    /// A compiled-in plugin (replaces r34's `admit_linked(&'static Plugin)`).
    pub fn linked(plugin: &'static LinkedPlugin) -> Result<Admitted, ImageError> {
        let admitted = Admitted {
            plugin: core::ptr::from_ref(plugin.header()).expose_provenance(),
        };
        match admitted.null_field() {
            Some(field) => Err(ImageError::Null(field)),
            None => Ok(admitted),
        }
    }

    /// The header.
    pub fn header(&self) -> &'static Plugin {
        let p = core::ptr::with_exposed_provenance::<Plugin>(self.plugin);
        // SAFETY: the address is a `LinkedPlugin` static or the bounds-checked header of an image whose
        // library `admit` leaked, so it is never unmapped (I13); the header is immutable.
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

    /// The kind table, if the stamp names `K`.
    pub(crate) fn vt<K: Kind>(&self) -> Option<&'static K::Vt> {
        if stamp_kind(self.stamp()) != K::CODE as u32 {
            return None;
        }
        let p = self.header().kind_vt_ptr().cast::<K::Vt>();
        // SAFETY: the stamp names `K`, so the table is `K::Vt`, one of busbar-ffi's own layouts (`Kind` is
        // sealed): a `LinkedPlugin`'s by `plugin()`'s kind check, a dropped-in image's by its build, and
        // `open` checked it lies, aligned and at `K::Vt`'s size, inside the never-unloaded image.
        Some(unsafe { &*p })
    }

    /// The first null header or table entry, named.
    pub fn null_field(&self) -> Option<&'static str> {
        if let Some(field) = self.header().null_field() {
            return Some(field);
        }
        match self.kind()? {
            KindCode::Store => self.vt::<kind::Store>()?.null_field(),
            KindCode::Secret => self.vt::<kind::Secret>()?.null_field(),
            KindCode::Auth => self.vt::<kind::Auth>()?.null_field(),
            KindCode::Hook => self.vt::<kind::Hook>()?.null_field(),
            KindCode::Export => self.vt::<kind::Export>()?.null_field(),
            KindCode::Plane => self.vt::<kind::Plane>()?.null_field(),
            KindCode::Transport => self.vt::<kind::Transport>()?.null_field(),
        }
    }
}
