// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host entry guard around every FFI entry (IF §10.7, I10). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-H0 fills it.

// W0-ABI: this file has no wave-0 items. The IF's §10.7 entry-guard items are both crate-private and have no
// caller until wave 1, so they land with W1-H0 (a crate-private item with no caller warns as dead code, and
// `host_side`'s `pub use entry::*` would warn that it re-exports nothing public):
//   pub(crate) enum EntryOwner<'a> {
//       Instance(&'a Instance),
//       Image { image: &'a Arc<Image>, slot: u32 },
//   }
//   pub(crate) fn guard<R>(owner: EntryOwner<'_>, entry: u8, out: Option<&mut PooledOut>,
//                          call: impl FnOnce(*mut RawOut) -> R) -> R;
// with the host-side `const`-initialised `thread_local!` cells `DEPTH: Cell<u32>` and `OWNER: Cell<u32>`
// (`u32::MAX` = none) that `guard` maintains and `watch::current_slot()` reads (IF §10.7, rounds 22 and 24).
