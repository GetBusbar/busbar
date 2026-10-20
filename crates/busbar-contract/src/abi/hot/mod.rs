// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The busbar **protocol-plane HOT-tier ABI** — a `#[repr(C)]`, POD-by-pointer, zero-alloc seam
//! between the neutral engine and a protocol plane (compiled in or `dlopen`ed).
//!
//! This is the HOT lane of [`busbar_plugin`](crate); the COLD lane (`abi::cold`, deleted) was its
//! deliberately-opposite sibling (JSON over six C symbols, off the request hot path). Both obeyed the
//! shared airlock preamble and sized-struct discipline hoisted to the [crate root](crate).
//!
//! Every type and signature here is real. The host side of the table is built by busbar-kernel's
//! `plane_host` (`build_plane_host_vtable`).
//!
//! # The disciplines this lane encodes (all frozen by construction)
//!
//! * **The airlock preamble** ([`AbiPreamble`](crate::abi::AbiPreamble),
//!   [`check_preamble`](crate::abi::check_preamble)) — shared with the cold lane, defined at the crate
//!   root and re-checked before any vtable slot is used.
//! * **Sized-struct / append-only discipline** — every cross-boundary POD struct here LEADS with a
//!   `size: u32` and a `version: u16`; a receiver reads a field only when `size` proves the sender
//!   wrote it (see [`read_sized_field`](crate::read_sized_field)). New fields may ONLY be appended.
//! * **`extern "C-unwind"` fn-pointer vtables** ([`host::PlaneHostVtable`]) —
//!   POD args by pointer, small results by value, large results into a caller
//!   `&mut MaybeUninit<Out>` written INSIDE a `catch_unwind` and marked init only on Ok (the
//!   [`write_out`](crate::abi::write_out) discipline). NO `Vec` returns on the hot calls.
//!
//! # Neutrality
//!
//! No type, function, variant, or carrier name in this lane may contain a protocol/role noun. A CI
//! witness (`scripts/plane-abi-neutrality.sh`) greps this module tree for the banned set and asserts
//! zero — proof the capability surface was DERIVED from a primitive taxonomy, not ENUMERATED from any
//! one plane.

pub mod host;
pub mod pod;

// Re-export the whole POD surface at the lane root so a plane author writes
// `crate::abi::hot::Facts`, not `crate::abi::hot::pod::Facts`.
pub use host::PlaneHostVtable;
pub use pod::*;
