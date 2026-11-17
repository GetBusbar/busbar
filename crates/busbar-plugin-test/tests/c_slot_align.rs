// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SLOT-ALIGN (ABI-MIN3-INTERFACE §14): Every slot address 128-byte aligned; `free_head` off the `pages` line.
//!
//! The arm runs in busbar-ffi: `Slot<T>`, `FreeHead` and the `pages`/`free` fields are private to busbar-ffi
//! `src/slots.rs`, so a slot address and the free head's line can only be read from inside that crate
//! (GetBusbar/busbar#265; WBS rule 10: the owner's crate):
//!
//! - TEST-VALUE `slots_are_128_byte_aligned`: `busbar_ffi::slots::tests::slots_are_128_byte_aligned`
//!   (crates/busbar-ffi/src/slots.rs). Four pages are filled on a table on the stack, a `static` table (as an
//!   image's open slab) and an instance's session and chain tables, over a 48-byte session state (the B-SYNC
//!   churn arm's), a `u64` and the chain box; every slot address of every page is 128-byte aligned, and the
//!   free head's bytes share no 128-byte line with `pages`.
