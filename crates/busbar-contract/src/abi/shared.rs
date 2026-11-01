// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SHARED SHAPES: the borrowed string and field, the connection facts and the closed
//! vocabularies as bytes that the memory ABI's connection table (`abi::host::conn`) carries. Their
//! one home is here, under `abi/` and outside the condemned HOT and COLD lanes (`BUSBAR-1.6.0.md`
//! THE DESIGN, the plugin ABI: the memory ABI alone).

/// A borrowed UTF-8 range — the `(ptr, len)` pair a declared vocabulary field spells out
/// inline, as one `#[repr(C)]` value so a list of them can be borrowed too. A NULL `ptr` is the
/// ABSENT value (an optional fact the plane does not state); a non-null `ptr` is a stated string,
/// even when `len` is 0. Like every decl range it MUST point at bytes that outlive the decl.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DeclStr {
    /// Borrowed UTF-8 bytes (NOT owned); NULL = absent.
    pub ptr: *const u8,
    /// Length of the range.
    pub len: usize,
}

impl DeclStr {
    /// The absent value: a NULL range.
    pub const NONE: DeclStr = DeclStr {
        ptr: core::ptr::null(),
        len: 0,
    };

    /// A stated string, borrowed for the life of the image.
    #[must_use]
    pub const fn new(s: &'static str) -> Self {
        DeclStr {
            ptr: s.as_ptr(),
            len: s.len(),
        }
    }

    /// A stated string that lives for the program: [`DeclStr::new`], named as
    /// [`AbiStr::of`](crate::abi::mechanism::call::AbiStr::of) is (status row 194).
    #[must_use]
    pub const fn of(s: &'static str) -> Self {
        Self::new(s)
    }

    /// The range `len` bytes at `ptr` name (NULL = absent), unchecked: the host's and the
    /// loader's door for the memory they lend one call (status row 194).
    ///
    /// # Safety
    ///
    /// Every read of the range finds `len` readable bytes at a non-NULL `ptr`, alive and unwritten
    /// for as long as that read.
    #[must_use]
    pub const unsafe fn from_raw_parts(ptr: *const u8, len: usize) -> Self {
        DeclStr { ptr, len }
    }

    /// The pointer (NULL = absent). Reading it is safe; reading through it is not.
    #[must_use]
    pub const fn ptr(&self) -> *const u8 {
        self.ptr
    }

    /// The length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the range is empty (absent or zero-length).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Whether the range is absent (NULL).
    #[must_use]
    pub const fn is_absent(&self) -> bool {
        self.ptr.is_null()
    }

    /// The bytes; empty when absent.
    ///
    /// # Safety
    ///
    /// The range names `len` readable bytes, alive and unwritten for `'a`: one made by
    /// [`DeclStr::new`] always does.
    #[must_use]
    pub unsafe fn bytes<'a>(&self) -> &'a [u8] {
        // SAFETY: the caller's contract.
        unsafe { crate::abi::abi_slice(self.ptr, self.len) }
    }
}

// SAFETY: a `DeclStr` is a borrowed range into the plugin image's own read-only bytes — the same
// lifetime contract (and the same reasoning) as every `*const u8` vocabulary field a plugin declares: mapped for the whole life of the loaded plugin, never mutated or freed while a decl that
// references them exists. A plane holds its lists of these in `static`s, which requires `Sync`.
unsafe impl Send for DeclStr {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for DeclStr {}

/// What connection security established ([`crate::transport::ConnFacts`]), borrowed for the call —
/// facts only; each string NULL when absent, and the certificate's three facts present together.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WireConnFacts {
    /// `size_of::<WireConnFacts>()` at construction.
    pub size: u32,
    /// Schema version.
    pub version: u32,
    /// The server name offered.
    pub sni: DeclStr,
    /// The protocol agreed.
    pub alpn: DeclStr,
    /// The far end's certificate subject.
    pub cert_subject: DeclStr,
    /// The far end's certificate issuer.
    pub cert_issuer: DeclStr,
    /// The far end's certificate fingerprint (NULL = no certificate).
    pub cert_fingerprint: DeclStr,
    /// The claim the host resolved the connection to (appended at minor 33; NULL = the entry's
    /// first claim).
    pub claim: DeclStr,
}

/// One envelope field: a name and its value.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WireField {
    /// The field name (UTF-8).
    pub name: DeclStr,
    /// Its value (any bytes).
    pub value: DeclStr,
}

// ── the closed vocabularies, as bytes ────────────────────────────────────────────────────────────

/// Every closed vocabulary a slot or the row carries crosses as a byte, `0` = absent where the
/// value is optional; these are the encodings, each with its inverse (an unknown byte is `None`).
pub mod code {
    use crate::grammar::SelectorForm;
    use crate::transport::wire::{Framing, StatusAt, Unit0Trigger, WireStatusClass};
    use crate::transport::Side;

    /// A status class, `1..=4`; `0` = none.
    #[must_use]
    pub const fn status_class(s: Option<WireStatusClass>) -> u8 {
        match s {
            None => 0,
            Some(WireStatusClass::Success) => 1,
            Some(WireStatusClass::CallerFault) => 2,
            Some(WireStatusClass::FarEndFault) => 3,
            Some(WireStatusClass::Other) => 4,
        }
    }

    /// The inverse of [`status_class`]; `Err` for an unknown byte.
    pub const fn status_class_of(b: u8) -> Result<Option<WireStatusClass>, u8> {
        Ok(match b {
            0 => None,
            1 => Some(WireStatusClass::Success),
            2 => Some(WireStatusClass::CallerFault),
            3 => Some(WireStatusClass::FarEndFault),
            4 => Some(WireStatusClass::Other),
            other => return Err(other),
        })
    }

    /// Which frame carries the status, `1..=2`; `0` = none.
    #[must_use]
    pub const fn status_at(s: Option<StatusAt>) -> u8 {
        match s {
            None => 0,
            Some(StatusAt::FirstFrame) => 1,
            Some(StatusAt::Terminal) => 2,
        }
    }

    /// How arrivals are delimited, `0..=1`.
    #[must_use]
    pub const fn framing(f: Framing) -> u8 {
        match f {
            Framing::Stream => 0,
            Framing::Datagram => 1,
        }
    }

    /// What opens a session's first unit, `1..=6`; `0` = none.
    #[must_use]
    pub const fn unit0_trigger(t: Option<Unit0Trigger>) -> u8 {
        match t {
            None => 0,
            Some(Unit0Trigger::FirstBytes) => 1,
            Some(Unit0Trigger::FirstLine) => 2,
            Some(Unit0Trigger::FirstMessage) => 3,
            Some(Unit0Trigger::FirstDatagram) => 4,
            Some(Unit0Trigger::Upgrade) => 5,
            Some(Unit0Trigger::Handshake) => 6,
        }
    }

    /// Every selector form, in code order: a form's code is its index here plus one.
    pub const SELECTOR_FORMS: [SelectorForm; 13] = [
        SelectorForm::ExactPath,
        SelectorForm::PrefixOneLevel,
        SelectorForm::Sni,
        SelectorForm::ClientCertSubject,
        SelectorForm::PathPattern,
        SelectorForm::HeaderExact,
        SelectorForm::HeaderPresent,
        SelectorForm::HeaderPrefix,
        SelectorForm::PathSuffix,
        SelectorForm::PathContains,
        SelectorForm::StreamName,
        SelectorForm::Alpn,
        SelectorForm::Port,
    ];

    /// A selector form's code, `1..=13`.
    #[must_use]
    pub const fn selector_form(f: SelectorForm) -> u8 {
        let mut i = 0;
        while i < SELECTOR_FORMS.len() {
            if SELECTOR_FORMS[i] as u8 == f as u8 {
                return i as u8 + 1;
            }
            i += 1;
        }
        0
    }

    /// Which end of a connection, `0..=1`.
    #[must_use]
    pub const fn side(s: Side) -> u8 {
        match s {
            Side::Accept => 0,
            Side::Dial => 1,
        }
    }

    /// The inverse of [`side`].
    #[must_use]
    pub const fn side_of(b: u8) -> Option<Side> {
        match b {
            0 => Some(Side::Accept),
            1 => Some(Side::Dial),
            _ => None,
        }
    }
}
