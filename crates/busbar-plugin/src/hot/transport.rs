// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`TransportDecl`] — the core→transport direction: the surface a **carrier** EXPORTS so core can
//! validate its config, build it (secrets PRE-RESOLVED to references, exactly like a plane's
//! [`build`](crate::hot::decl::BuildFn)), and drive its BIDIRECTIONAL byte-stream carrier — the two
//! directions of the ONE transport kind (`DECISIONS #3`: "TRANSPORT is one kind, bidirectional"):
//!
//! * the ACCEPT direction ([`AcceptFn`]) — the passive/listen side (server-accept a bounded byte
//!   stream), and
//! * the CONNECT direction ([`ConnectFn`]) — the active/dial side (client-connect to a destination),
//!
//! both feeding the same [`WriteFn`]/[`ReadFn`] bounded byte pump. This mirrors the carrier surface
//! the compiled-in `busbar-transport-{http,ws,stdio,tcp,tls,sse,grpc}` crates already implement
//! (`busbar_contract::transport::Transport`'s `listen`/`accept`/`dial`/`frames`/`write`/`close`),
//! re-expressed in ABI-safe POD primitives — it does NOT change, borrow, or cross that shipped trait.
//!
//! Same `#[repr(C)]` discipline as [`PlaneDecl`](super::decl::PlaneDecl): a FROZEN [`AbiPreamble`]
//! preamble, a sized/versioned header, `extern "C-unwind"` fn-pointer slots, POD args by pointer and
//! large results into a caller `&mut MaybeUninit<Out>` written INSIDE a `catch_unwind` and marked init
//! only on Ok (the [`write_out`](crate::write_out) discipline). A connection is a plane-owned
//! [`OpaqueHandle`] (a `*mut c_void` plus a never-panics `free`), exactly like a plane's built state —
//! closing a connection is calling its `free`, so the carrier needs no separate close symbol.
//!
//! This lane is ADDITIVE and UNUSED by the engine's live carriers: the seven compiled-in transports
//! stay exactly as they are. It is the DROP-IN ABI that closes the both-ways gap for `kind: transport`
//! (`DECISIONS #11`: every plugin kind must be both compiled-in AND droppable), proven by the in-tree
//! `busbar-plugin-example-transport` fixture the way `kind: plane` is proven by the example plane.

use super::decl::{BuildFn, ConfigValidateFn, OpaqueHandle};
use super::pod::RawStatus;
use crate::AbiPreamble;
use core::mem::MaybeUninit;
use std::os::raw::c_void;

/// The two DIRECTIONS of the one bidirectional transport kind. A [`TransportDecl`] declares WHICH it
/// provides via [`TransportDecl::provided_facets`] (a bidirectional carrier provides BOTH); the host
/// drives them uniformly. Direction is a USAGE MODE, never a kind boundary (`DECISIONS #3`), so the
/// axis is binary — a carrier is passive-capable, active-capable, or both — with no reserved slack.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportFacet {
    /// The PASSIVE side: bind-and-accept an inbound bounded byte stream (the "server-accept" facet;
    /// `transport-key` is this facet, `DECISIONS #3`). Driven through [`AcceptFn`].
    Accept = 0,
    /// The ACTIVE side: dial an outbound destination (the "client-connect" facet). Driven through
    /// [`ConnectFn`].
    Connect = 1,
}

impl TransportFacet {
    /// The single-bit mask for this facet in [`TransportDecl::provided_facets`].
    #[inline]
    #[must_use]
    pub const fn bit(self) -> u32 {
        1u32 << (self as u32)
    }

    /// The mask of BOTH directions — a fully bidirectional carrier.
    #[inline]
    #[must_use]
    pub const fn bidirectional() -> u32 {
        TransportFacet::Accept.bit() | TransportFacet::Connect.bit()
    }
}

// ── core→transport fn-pointer signatures (all `extern "C-unwind"`, POD by pointer) ────────────────

/// ACCEPT one inbound connection (the passive/server-accept side), producing the plane-owned opaque
/// [`OpaqueHandle`] for the accepted bounded byte stream on `Ok`. `state` is the built carrier handle.
pub type AcceptFn =
    extern "C-unwind" fn(state: *mut c_void, out_conn: *mut MaybeUninit<OpaqueHandle>) -> RawStatus;

/// CONNECT to a destination (the active/client-connect side), producing the opaque connection handle
/// on `Ok`. `dest` is the borrowed destination descriptor bytes (opaque to core), live for the call.
pub type ConnectFn = extern "C-unwind" fn(
    state: *mut c_void,
    dest_ptr: *const u8,
    dest_len: usize,
    out_conn: *mut MaybeUninit<OpaqueHandle>,
) -> RawStatus;

/// WRITE `len` bytes into a connection; sets `out_written` to how many were accepted. `conn` is the
/// `ptr` of an [`OpaqueHandle`] an `Ok` [`AcceptFn`]/[`ConnectFn`] produced.
pub type WriteFn = extern "C-unwind" fn(
    conn: *mut c_void,
    buf: *const u8,
    len: usize,
    out_written: *mut usize,
) -> RawStatus;

/// READ up to `cap` bytes out of a connection into a caller buffer; sets `out_written` to how many
/// were produced (0 = nothing available). The bounded pull half of the byte pump.
pub type ReadFn = extern "C-unwind" fn(
    conn: *mut c_void,
    buf: *mut u8,
    cap: usize,
    out_written: *mut usize,
) -> RawStatus;

/// The `#[repr(C)]` surface a transport carrier exports for core to drive. Leads with the FROZEN
/// [`AbiPreamble`] and a sized/versioned header; carries the carrier's vocabulary (borrowed
/// name/section-key/scope/label, exactly like [`PlaneDecl`](super::decl::PlaneDecl)), the set of
/// directions it provides, and the fn-pointer slots. `None` slots are absent capabilities (a
/// connect-only carrier leaves `accept` `None`, and vice-versa).
///
/// # Safety / discipline
/// The vocabulary `(ptr, len)` ranges MUST point at bytes that outlive the decl (the plugin image's
/// own `'static` read-only strings) — the same contract [`PlaneDecl`](super::decl::PlaneDecl) documents.
#[repr(C)]
pub struct TransportDecl {
    /// The FROZEN airlock header — core `check_preamble`s it before using any slot.
    pub abi: AbiPreamble,
    /// `size_of::<TransportDecl>()` at construction (the sized-struct guard).
    pub size: u32,
    /// Decl schema version (bumped when a trailing slot/field is appended).
    pub version: u32,

    /// Borrowed carrier name bytes (vocabulary; NOT owned).
    pub name_ptr: *const u8,
    /// Length of the name range.
    pub name_len: usize,
    /// Borrowed config section-key bytes (NOT owned).
    pub section_key_ptr: *const u8,
    /// Length of the section-key range.
    pub section_key_len: usize,
    /// Borrowed scope label bytes (NOT owned).
    pub scope_ptr: *const u8,
    /// Length of the scope range.
    pub scope_len: usize,
    /// Borrowed human label bytes (NOT owned).
    pub label_ptr: *const u8,
    /// Length of the label range.
    pub label_len: usize,

    /// Bitset of the [`TransportFacet`]s this carrier provides (OR of [`TransportFacet::bit`]).
    pub provided_facets: u32,
    /// Preamble/alignment padding.
    pub _reserved: u32,

    /// Validate raw config, producing a parsed opaque handle (shared shape with a plane's slot).
    pub config_validate: Option<ConfigValidateFn>,
    /// Build the carrier (secrets pre-resolved), producing the opaque carrier handle.
    pub build: Option<BuildFn>,
    /// Accept an inbound connection (passive/server-accept side).
    pub accept: Option<AcceptFn>,
    /// Connect to a destination (active/client-connect side).
    pub connect: Option<ConnectFn>,
    /// Write bytes into a connection.
    pub write: Option<WriteFn>,
    /// Read bytes out of a connection.
    pub read: Option<ReadFn>,
}

// SAFETY: `TransportDecl` holds `AbiPreamble` scalars, `Option<extern "C-unwind" fn>` slots, and
// genuine `*const u8` vocabulary fields — identical to `PlaneDecl`. Raw pointers are NOT auto-Send/Sync,
// so these hand-written impls are load-bearing. The soundness contract is the same as `PlaneDecl`'s:
// every `*const u8` points INTO the plugin image's own read-only vocabulary strings, mapped for the
// whole life of the loaded image and never mutated or freed while any `TransportDecl` referencing them
// exists. Core holds `&TransportDecl` across `.await` and worker threads; the pointees outlive every
// such borrow because the image does.
unsafe impl Send for TransportDecl {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for TransportDecl {}

impl TransportDecl {
    /// True iff this decl declares it provides `facet`.
    #[inline]
    #[must_use]
    pub fn provides(&self, facet: TransportFacet) -> bool {
        self.provided_facets & facet.bit() != 0
    }

    /// A fully-populated STUB decl for one bidirectional carrier, every slot an `unimplemented!()`
    /// stub. It PROVES the whole export surface type-checks; a real carrier replaces the stubs.
    /// Invoking any slot panics.
    pub const STUB: TransportDecl = TransportDecl {
        abi: AbiPreamble::CURRENT,
        size: core::mem::size_of::<TransportDecl>() as u32,
        version: crate::ABI_MINOR,
        name_ptr: core::ptr::null(),
        name_len: 0,
        section_key_ptr: core::ptr::null(),
        section_key_len: 0,
        scope_ptr: core::ptr::null(),
        scope_len: 0,
        label_ptr: core::ptr::null(),
        label_len: 0,
        provided_facets: TransportFacet::bidirectional(),
        _reserved: 0,
        config_validate: Some(stub::config_validate),
        build: Some(stub::build),
        accept: Some(stub::accept),
        connect: Some(stub::connect),
        write: Some(stub::write),
        read: Some(stub::read),
    };
}

/// The `unimplemented!()` stub carrier exports backing [`TransportDecl::STUB`]. Each has the EXACT
/// fn-pointer signature of its slot — the type-level proof the export surface compiles. A real carrier
/// replaces each with an impl that runs INSIDE a `catch_unwind` and writes out-params only on Ok.
pub mod stub {
    use super::super::decl::BuildCtx;
    use super::*;

    /// Stub: see module docs.
    pub extern "C-unwind" fn config_validate(
        _raw_ptr: *const u8,
        _raw_len: usize,
        _out_parsed: *mut MaybeUninit<OpaqueHandle>,
    ) -> RawStatus {
        unimplemented!("TransportDecl::config_validate — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn build(
        _ctx: *const BuildCtx,
        _out_handle: *mut MaybeUninit<OpaqueHandle>,
    ) -> RawStatus {
        unimplemented!("TransportDecl::build — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn accept(
        _state: *mut c_void,
        _out_conn: *mut MaybeUninit<OpaqueHandle>,
    ) -> RawStatus {
        unimplemented!("TransportDecl::accept — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn connect(
        _state: *mut c_void,
        _dest_ptr: *const u8,
        _dest_len: usize,
        _out_conn: *mut MaybeUninit<OpaqueHandle>,
    ) -> RawStatus {
        unimplemented!("TransportDecl::connect — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn write(
        _conn: *mut c_void,
        _buf: *const u8,
        _len: usize,
        _out_written: *mut usize,
    ) -> RawStatus {
        unimplemented!("TransportDecl::write — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn read(
        _conn: *mut c_void,
        _buf: *mut u8,
        _cap: usize,
        _out_written: *mut usize,
    ) -> RawStatus {
        unimplemented!("TransportDecl::read — stub")
    }
}

#[cfg(test)]
#[path = "tests/transport_tests.rs"]
mod tests;
