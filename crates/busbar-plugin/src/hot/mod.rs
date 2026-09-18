// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The busbar **protocol-plane HOT-tier ABI** — a `#[repr(C)]`, POD-by-pointer, zero-alloc seam
//! between the neutral engine and a protocol plane (compiled-in or, later, `dlopen`ed).
//!
//! This is the HOT lane of [`busbar_plugin`](crate); the [`cold`](crate::cold) lane is its
//! deliberately-opposite sibling (JSON over six C symbols, off the request hot path). Both obey the
//! shared airlock preamble and sized-struct discipline hoisted to the [crate root](crate).
//!
//! This lane is the FOUNDATION skeleton: every type and signature is real, every impl is a stub
//! (`unimplemented!()` / defaults). It is ADDITIVE and UNUSED — nothing in the engine calls it yet;
//! a later phase wires it in. Downstream plane authors build capability impls against these types.
//!
//! # The disciplines this lane encodes (all frozen by construction)
//!
//! * **The airlock preamble** ([`AbiPreamble`](crate::AbiPreamble),
//!   [`check_preamble`](crate::check_preamble)) — shared with the cold lane, defined at the crate
//!   root and re-checked before any vtable slot is used.
//! * **Sized-struct / append-only discipline** — every cross-boundary POD struct here LEADS with a
//!   `size: u32` and a `version: u16`; a receiver reads a field only when `size` proves the sender
//!   wrote it (see [`read_sized_field`](crate::read_sized_field)). New fields may ONLY be appended.
//! * **`extern "C-unwind"` fn-pointer vtables** ([`host::PlaneHostVtable`], [`decl::PlaneDecl`]) —
//!   POD args by pointer, small results by value, large results into a caller
//!   `&mut MaybeUninit<Out>` written INSIDE a `catch_unwind` and marked init only on Ok (the
//!   [`write_out`](crate::write_out) discipline). NO `Vec` returns on the hot calls.
//!
//! # Neutrality
//!
//! No type, function, variant, or carrier name in this lane may contain a protocol/role noun. A CI
//! witness (`scripts/plane-abi-neutrality.sh`) greps this module tree for the banned set and asserts
//! zero — proof the capability surface was DERIVED from a primitive taxonomy, not ENUMERATED from any
//! one plane.

pub mod decl;
pub mod host;
pub mod pod;
pub mod transport;
pub mod workitem;

/// The cdylib ENTRYPOINT convention a dropped-in plane exports so the loader can recover its
/// [`PlaneDecl`]. This is the HOT-lane analogue of the cold lane's six `busbar_*` symbols
/// ([`crate::cold::symbol`]): a plane `cdylib` still exports `busbar_abi()` (the SHARED
/// [`TRANSPORT_VERSION`](crate::cold::TRANSPORT_VERSION) handshake) and `busbar_plugin_kind()` (==
/// `"plane"`, [`crate::cold::kind::PLANE`]) so it rides the EXACT same tarball / signed-manifest /
/// trust discovery pipeline; the ONE extra symbol below is how it hands core the `#[repr(C)]` decl
/// pointer instead of the JSON `call` wire.
pub mod symbol {
    /// `busbar_plane_decl() -> *const PlaneDecl` — the plane's ONE hot-lane entrypoint. Returns a
    /// pointer to a `'static` [`PlaneDecl`](super::PlaneDecl) owned by the library (its
    /// `#[repr(C)]` vtable, leading with the FROZEN [`AbiPreamble`](crate::AbiPreamble) the loader
    /// `check_preamble`s before reading any slot). The loader NEVER frees it — it lives for the life
    /// of the mapped image, exactly like the vocabulary strings the decl points into.
    pub const PLANE_DECL: &[u8] = b"busbar_plane_decl\0";

    /// `busbar_transport_decl() -> *const TransportDecl` — a `kind: transport` carrier's ONE hot-lane
    /// entrypoint, the exact analogue of [`PLANE_DECL`]. Returns a pointer to a `'static`
    /// [`TransportDecl`](super::TransportDecl) owned by the library (its `#[repr(C)]` vtable, leading
    /// with the FROZEN [`AbiPreamble`](crate::AbiPreamble) the loader `check_preamble`s before reading
    /// any slot). The loader NEVER frees it — it lives for the life of the mapped image. A carrier
    /// rides the SAME `busbar_abi`/`busbar_plugin_kind` (== `"transport"`) handshake as every kind, so
    /// it shares the tarball / signed-manifest / trust pipeline; this ONE extra symbol is how it hands
    /// core the bidirectional-carrier vtable instead of the JSON `call` wire.
    pub const TRANSPORT_DECL: &[u8] = b"busbar_transport_decl\0";
}

/// `busbar_plane_decl` — the plane cdylib entrypoint's fn-pointer type the loader resolves via
/// `libloading`. `unsafe extern "C-unwind"` for parity with the cold [`AbiFn`](crate::cold::AbiFn):
/// a panic in a plane's decl accessor unwinds as a DEFINED forced unwind the loader's guard catches,
/// rather than aborting at the plugin frame.
///
/// # Safety
/// The returned pointer, when non-null, must address a `'static` [`PlaneDecl`] whose bytes (and the
/// vocabulary ranges it points into) live for the whole life of the loaded library.
pub type PlaneDeclFn = unsafe extern "C-unwind" fn() -> *const PlaneDecl;

/// `busbar_transport_decl` — the transport-carrier cdylib entrypoint's fn-pointer type the loader
/// resolves via `libloading`. The transport analogue of [`PlaneDeclFn`]; `unsafe extern "C-unwind"`
/// for the same reason (a panic in the accessor unwinds as a DEFINED forced unwind the loader's guard
/// catches, rather than aborting at the plugin frame).
///
/// # Safety
/// The returned pointer, when non-null, must address a `'static` [`TransportDecl`] whose bytes (and
/// the vocabulary ranges it points into) live for the whole life of the loaded library.
pub type TransportDeclFn = unsafe extern "C-unwind" fn() -> *const TransportDecl;

// Re-export the whole POD surface at the lane root so a plane author writes
// `busbar_plugin::hot::Facts`, not `busbar_plugin::hot::pod::Facts`.
pub use decl::{BuildCtx, IngressCarrier, OpaqueHandle, PlaneDecl};
pub use host::PlaneHostVtable;
pub use pod::*;
pub use transport::{TransportDecl, TransportFacet};
pub use workitem::{EmitHandle, EmitKind, InboundHandle, InboundKind, WorkItem};
