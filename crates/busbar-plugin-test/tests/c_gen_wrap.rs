// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-GEN-WRAP (ABI-MIN3-INTERFACE §14): The slot's 31-bit generation forced to 2^31-2 and wrapped; ChainId still
//! differs.
//!
//! The arm runs in busbar-ffi, beside the slot table it pins. `Slot<T>` and its generation are private to
//! busbar-ffi `src/slots.rs`, and the hook that forces a free slot's generation (`Slots::force_generation`, the
//! IF's `busbar_abi_test` hook) exists only in that crate's test build, so a release build never carries it
//! (GetBusbar/busbar#265; WBS rule 10: the owner's crate):
//!
//! - TEST-VALUE `a_wrapped_generation_keeps_chain_ids_distinct`:
//!   `busbar_ffi::slots::tests::a_wrapped_generation_keeps_chain_ids_distinct` (crates/busbar-ffi/src/slots.rs).
//!   The slot's generation is forced to 2^31-2; the free list hands the same slot back as the generation runs
//!   2^31-2, 2^31-1 and wraps to 1 (never 0), so the slot's first chain token comes round again, while every
//!   older generation stays stale and every ChainId differs. Bytes stashed by the first chain are refused under
//!   the chain that now holds its token, and read under their own.
