// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plugin-side bridge: the entry wrapper, chain polling and the `CURRENT` restore the shims use (IF §6.2, §6.4). W0-ABI stub: frozen signatures, `todo!()` bodies; A3 fills it.
//!
//! W0-ABI: §6.4 is prose. It names `entry(|| ..)` (step 0), the one `poll_chain` fn (§6.2), the shims' start,
//! resume, cancel and close steps, `bridge::thread_ordinal()` (§6.5 failure branch), `ChainBox`, `Inbox` and
//! `Current`, but gives none of them a signature, so none is written here; W1-A3 adds them with the shims.

use core::marker::PhantomData;

/// Sets CURRENT = (out, id, step, inbox) for one poll (round 13: `step` = the chain's step counter, §6.4 step 4); `Drop` writes back exactly the values it read at `set`, on
/// return **and on unwind**. `!Send`, `!Sync`, never stored, never `mem::forget`-ten (it is a local of the one
/// `poll_chain` fn). Two thread-local loads and two stores at set, two stores at drop; no RMW, no allocation (I5).
#[doc(hidden)]
pub struct CurrentGuard {
    // W0-ABI: `pub(crate)` in the IF; `#[doc(hidden)] pub` here so the unused stub is not dead code. The IF
    // fields `prev: Current, prev_inbox: *const Inbox` name types the IF does not define (W1-A3 adds them).
    _ns: PhantomData<*const ()>,
}
// W0-ABI: `impl CurrentGuard { pub(crate) fn set(out: *mut RawOut, id: ChainId, step: u32, inbox: *const Inbox)
// -> CurrentGuard; }` lands with W1-A3: `Inbox` is not defined by the IF, and the fn would be dead code here.
// W0-ABI: `impl Drop for CurrentGuard { fn drop(&mut self); }` lands with W1-A3 (no `impl Drop` in W0 stubs).
