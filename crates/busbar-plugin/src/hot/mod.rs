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
pub mod workitem;

// Re-export the whole POD surface at the lane root so a plane author writes
// `busbar_plugin::hot::Facts`, not `busbar_plugin::hot::pod::Facts`.
pub use decl::{BuildCtx, IngressCarrier, OpaqueHandle, PlaneDecl};
pub use host::PlaneHostVtable;
pub use pod::*;
pub use workitem::{EmitHandle, EmitKind, InboundHandle, InboundKind, WorkItem};
